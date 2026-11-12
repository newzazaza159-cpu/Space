// ===== Space Shooter Sync Server (บัญชี + เซฟบน Google Drive) =====
// ดัดแปลงจากเซิร์ฟเวอร์ Card RNG: เหลือเฉพาะ สมัคร/ล็อกอิน/เซฟ/อันดับ/แอดมิน
// แยกโฟลเดอร์ Drive และ secret ออกจากเกมการ์ดโดยสิ้นเชิง (ตั้งผ่าน env)

try { require("dotenv").config(); } catch (e) { /* ไม่มี dotenv ก็ใช้ env ของระบบ */ }

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Readable } = require("stream");
const { google } = require("googleapis");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "";                 // ว่าง = ปิดคำสั่งแอดมินทั้งหมด
const FOLDER_NAME = process.env.DRIVE_FOLDER_NAME || "SpaceShooter";
const PLAYERS_FOLDER = FOLDER_NAME + "-players";
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const TOKEN_TTL_MS = 30 * 24 * 3600 * 1000;
const MAX_SAVE_BYTES = 2 * 1024 * 1024;

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN } = process.env;
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REFRESH_TOKEN) console.error("❌ ยังไม่ได้ตั้ง GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN");
if (!TOKEN_SECRET || TOKEN_SECRET.length < 16) console.error("❌ ต้องตั้ง TOKEN_SECRET (สุ่มยาว ๆ ไม่ซ้ำกับเกมการ์ด)");

const auth = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
auth.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });
const drive = google.drive({ version: "v3", auth });

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "3mb" }));

// ---------- Drive: โฟลเดอร์ผู้เล่น ----------
let folderPromise = null;
function getPlayersFolderId() {
    if (!folderPromise) {
        folderPromise = (async () => {
            const q = `mimeType='application/vnd.google-apps.folder' and name='${PLAYERS_FOLDER}' and trashed=false`;
            const r = await drive.files.list({ q, fields: "files(id)", spaces: "drive" });
            if (r.data.files && r.data.files.length) return r.data.files[0].id;
            const c = await drive.files.create({ requestBody: { name: PLAYERS_FOLDER, mimeType: "application/vnd.google-apps.folder" }, fields: "id" });
            return c.data.id;
        })().catch(e => { folderPromise = null; throw e; });
    }
    return folderPromise;
}

const nameKey = n => String(n || "").trim().toLowerCase();
const playerFileName = key => "player_" + Buffer.from(key, "utf8").toString("hex") + ".json";
const playerLocks = new Map();   // คิวเขียนต่อชื่อ กันเขียนชนกัน
function withLock(key, fn) {
    const prev = playerLocks.get(key) || Promise.resolve();
    const next = prev.catch(() => {}).then(fn);
    playerLocks.set(key, next.catch(() => {}));
    return next;
}
const playerIdCache = new Map();
async function findPlayerFile(key) {
    if (playerIdCache.has(key)) return playerIdCache.get(key);
    const parent = await getPlayersFolderId();
    const r = await drive.files.list({ q: `name='${playerFileName(key)}' and '${parent}' in parents and trashed=false`, fields: "files(id)", spaces: "drive" });
    const id = r.data.files && r.data.files[0] ? r.data.files[0].id : null;
    if (id) playerIdCache.set(key, id);
    return id;
}
async function readPlayer(id) {
    const f = await drive.files.get({ fileId: id, alt: "media" }, { responseType: "text" });
    return typeof f.data === "string" ? JSON.parse(f.data) : f.data;
}
async function writePlayer(id, obj) {
    const body = Readable.from(Buffer.from(JSON.stringify(obj)));
    if (id) { await drive.files.update({ fileId: id, media: { mimeType: "application/json", body } }); return id; }
    const parent = await getPlayersFolderId();
    const c = await drive.files.create({ requestBody: { name: playerFileName(nameKey(obj.name)), parents: [parent] }, media: { mimeType: "application/json", body }, fields: "id" });
    return c.data.id;
}

// ---------- รหัสผ่าน / โทเคน ----------
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 64).toString("hex");
function makeToken(key) {
    const body = Buffer.from(JSON.stringify({ k: key, e: Date.now() + TOKEN_TTL_MS })).toString("base64url");
    return body + "." + crypto.createHmac("sha256", TOKEN_SECRET).update(body).digest("base64url");
}
function readToken(tok) {
    const [body, sig] = String(tok || "").split(".");
    if (!body || !sig || !TOKEN_SECRET) return null;
    const good = crypto.createHmac("sha256", TOKEN_SECRET).update(body).digest("base64url");
    if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
    try { const o = JSON.parse(Buffer.from(body, "base64url").toString()); return o.e > Date.now() ? o.k : null; } catch (e) { return null; }
}
function requirePlayer(req, res, next) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
    const key = m && readToken(m[1]);
    if (!key) return res.status(401).json({ error: "เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่" });
    req.playerKey = key; next();
}
function requireAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];
    if (!ADMIN_KEY || !key || key !== ADMIN_KEY) return res.status(401).json({ error: "รหัสผ่านแอดมินไม่ถูกต้อง" });
    next();
}
// จำกัดการเดารหัส: ต่อ IP ไม่เกิน 15 ครั้ง / 10 นาที
const attempts = new Map();
function rateLimit(req, res, next) {
    const now = Date.now(), ip = req.ip, a = (attempts.get(ip) || []).filter(t => now - t < 600000);
    if (a.length >= 15) return res.status(429).json({ error: "ลองหลายครั้งเกินไป รอสักครู่แล้วลองใหม่" });
    a.push(now); attempts.set(ip, a);
    if (attempts.size > 5000) for (const [k, v] of attempts) if (!v.some(t => now - t < 600000)) attempts.delete(k);
    next();
}
// เซฟของเกมนี้ = object แบนของค่า localStorage ที่ขึ้นต้นด้วย ss_ (เช่น { ss_coin:"123", ss_lv:"5", ... })
function checkSave(save) {
    if (save != null && (typeof save !== "object" || Array.isArray(save))) return "ข้อมูลเซฟไม่ถูกต้อง";
    if (save && Buffer.byteLength(JSON.stringify(save)) > MAX_SAVE_BYTES) return "ข้อมูลเซฟใหญ่เกินไป";
    return null;
}

// ---------- สมัคร / ล็อกอิน ----------
app.post("/api/accounts/register", rateLimit, async (req, res) => {
    try {
        const { name, password, save } = req.body || {};
        const clean = String(name || "").trim();
        if (!clean || clean.length > 24) return res.status(400).json({ error: "ชื่อต้องยาว 1-24 ตัวอักษร" });
        if (typeof password !== "string" || password.length < 6 || password.length > 100) return res.status(400).json({ error: "รหัสผ่านต้องยาว 6-100 ตัว" });
        const bad = checkSave(save); if (bad) return res.status(400).json({ error: bad });
        const key = nameKey(clean);
        await withLock(key, async () => {
            if (await findPlayerFile(key)) { const e = new Error("ชื่อนี้ถูกใช้แล้ว"); e.status = 409; throw e; }
            const salt = crypto.randomBytes(16).toString("hex");
            const id = await writePlayer(null, { name: clean, salt, hash: hashPw(password, salt), save: save || null, created: Date.now(), updatedAt: Date.now() });
            playerIdCache.set(key, id);
        });
        res.json({ ok: true, name: clean, token: makeToken(key) });
    } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

app.post("/api/accounts/login", rateLimit, async (req, res) => {
    try {
        const { name, password } = req.body || {};
        const key = nameKey(name), id = key && await findPlayerFile(key);
        const bad = () => res.status(401).json({ error: "ชื่อหรือรหัสผ่านไม่ถูกต้อง" });
        if (!id || typeof password !== "string") return bad();
        const p = await readPlayer(id);
        const h = Buffer.from(hashPw(password, p.salt), "hex"), want = Buffer.from(p.hash, "hex");
        if (h.length !== want.length || !crypto.timingSafeEqual(h, want)) return bad();
        res.json({ ok: true, name: p.name, token: makeToken(key), save: p.save || null, updatedAt: p.updatedAt || 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- เซฟ ----------
app.get("/api/accounts/save", requirePlayer, async (req, res) => {
    try {
        res.set("Cache-Control", "no-store");
        const id = await findPlayerFile(req.playerKey); if (!id) return res.status(404).json({ error: "ไม่พบบัญชี" });
        const p = await readPlayer(id);
        res.json({ name: p.name, save: p.save || null, updatedAt: p.updatedAt || 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put("/api/accounts/save", requirePlayer, async (req, res) => {
    try {
        const { save } = req.body || {};
        if (!save) return res.status(400).json({ error: "ไม่มีข้อมูลเซฟ" });
        const bad = checkSave(save); if (bad) return res.status(400).json({ error: bad });
        const key = req.playerKey;
        const updatedAt = await withLock(key, async () => {
            const id = await findPlayerFile(key); if (!id) { const e = new Error("ไม่พบบัญชี"); e.status = 404; throw e; }
            const p = await readPlayer(id);
            p.save = save; p.updatedAt = Date.now();
            await writePlayer(id, p);
            const row = lbRowOf(p); if (row) { lbRows.set(key, row); lbAt = Date.now(); }
            return p.updatedAt;
        });
        res.json({ ok: true, updatedAt });
    } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// ---------- อันดับ (เรียงตามเหรียญ ss_coin) ----------
const LB_TTL_MS = 10 * 60 * 1000;
let lbRows = new Map(), lbAt = 0, lbScanAt = 0, lbBusy = null;
const num = v => { const n = Number(v); return Number.isFinite(n) ? n : null; };
function lbRowOf(p) {
    const s = p && p.save;
    if (!p || !p.name || !s) return null;
    const coin = num(s.ss_coin);
    if (coin === null) return null;
    const lv = Math.floor(num(s.ss_lv) || 1);
    return { name: p.name, level: lv > 0 ? lv : 1, coin, gem: num(s.ss_gem) || 0 };
}
async function listPlayerFiles() {
    const parent = await getPlayersFolderId();
    const files = []; let pageToken;
    do {
        const r = await drive.files.list({ q: `'${parent}' in parents and trashed=false`, fields: "nextPageToken, files(id)", pageSize: 200, pageToken, spaces: "drive" });
        files.push(...(r.data.files || [])); pageToken = r.data.nextPageToken;
    } while (pageToken);
    return files;
}
function lbRefresh() {
    if (!lbBusy) {
        lbBusy = (async () => {
            const files = await listPlayerFiles();
            const next = new Map(); let readFail = 0;
            for (let i = 0; i < files.length; i += 5) {
                await Promise.all(files.slice(i, i + 5).map(async f => {
                    try { const row = lbRowOf(await readPlayer(f.id)); if (row) next.set(nameKey(row.name), row); } catch (e) { readFail++; }
                }));
            }
            if (readFail && readFail === files.length && files.length) throw new Error("อ่านไฟล์ผู้เล่นไม่สำเร็จ");   // พังทั้งหมด -> คงตารางเดิม
            lbRows = next; lbAt = lbScanAt = Date.now();
        })().finally(() => { lbBusy = null; });
    }
    return lbBusy;
}
app.get("/api/accounts/leaderboard", async (req, res) => {
    try {
        if (!lbScanAt) await lbRefresh();
        const rows = Array.from(lbRows.values()).sort((a, b) => b.coin - a.coin);
        res.set("Cache-Control", "no-store");
        res.json({ top: rows.slice(0, 50), total: rows.length, updatedAt: lbAt });
    } catch (e) { res.status(500).json({ error: e.message }); }
});
setInterval(() => { if (lbScanAt) lbRefresh().catch(() => {}); }, LB_TTL_MS).unref();

// ---------- แอดมิน ----------
app.get("/api/accounts/admin/list", requireAdmin, async (req, res) => {
    try {
        const files = await listPlayerFiles(); const players = [];
        for (let i = 0; i < files.length; i += 5) {
            await Promise.all(files.slice(i, i + 5).map(async f => {
                try {
                    const p = await readPlayer(f.id); if (!p || !p.name) return;
                    const row = lbRowOf(p);
                    players.push({ name: p.name, level: row ? row.level : 1, coin: row ? row.coin : null, created: p.created || 0, updatedAt: p.updatedAt || 0 });
                } catch (e) {}
            }));
        }
        players.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
        res.json({ players, total: players.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/accounts/:name", requireAdmin, async (req, res) => {
    try {
        const key = nameKey(req.params.name);
        if (!key) return res.status(400).json({ error: "ไม่มีชื่อไอดี" });
        await withLock(key, async () => {
            playerIdCache.delete(key);
            const id = await findPlayerFile(key);
            if (!id) { const e = new Error("ไม่พบไอดีนี้บนเซิร์ฟเวอร์"); e.status = 404; throw e; }
            await drive.files.delete({ fileId: id });
            playerIdCache.delete(key);
        });
        lbRows.delete(key); lbAt = Date.now();
        res.json({ ok: true });
    } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// ---------- ห้องเล่นกับเพื่อน (เก็บในหน่วยความจำ ไม่แตะ Drive / ไม่เกี่ยวกับเซฟ) ----------
// โฮสต์ส่ง heartbeat ทุก ~8 วิ; ห้องที่เงียบเกิน 25 วิ ถือว่าปิดแล้ว
const ROOM_TTL_MS = 25000, rooms = new Map(), roomHits = new Map();
const roomLimit = (req, res, next) => {
    const now = Date.now(), a = (roomHits.get(req.ip) || []).filter(t => now - t < 60000);
    if (a.length >= 120) return res.status(429).json({ error: "ช้าลงหน่อย" });
    a.push(now); roomHits.set(req.ip, a);
    if (roomHits.size > 5000) for (const [k, v] of roomHits) if (!v.some(t => now - t < 60000)) roomHits.delete(k);
    next();
};
const roomClean = () => { const now = Date.now(); for (const [c, r] of rooms) if (now - r.at > ROOM_TTL_MS) rooms.delete(c); };
app.get("/api/rooms", roomLimit, (req, res) => {
    roomClean(); res.set("Cache-Control", "no-store");
    res.json({ rooms: Array.from(rooms.values()).map(r => ({ code: r.code, name: r.name, mission: r.mission, count: r.count, playing: r.playing, guest: r.guest })) });   // แสดงทุกห้อง: รอ (count 1) / เต็ม (count 2) / กำลังเล่น (playing 1)
});
app.post("/api/rooms/:code", roomLimit, (req, res) => {
    const code = String(req.params.code || "").toUpperCase();
    if (!/^[A-Z0-9]{4}$/.test(code)) return res.status(400).json({ error: "รหัสห้องไม่ถูกต้อง" });
    roomClean(); if (!rooms.has(code) && rooms.size >= 300) return res.status(503).json({ error: "ห้องเต็ม" });
    const b = req.body || {}, name = String(b.name || "").replace(/[<>&"'`]/g, "").trim().slice(0, 24) || ("ผู้เล่น " + code);
    const mission = Math.max(0, Math.min(99, parseInt(b.mission, 10) || 0)), count = parseInt(b.count, 10) === 2 ? 2 : 1;
    const playing = (b.playing === 1 || b.playing === true || b.playing === "1") ? 1 : 0;
    const guest = count === 2 ? String(b.guest || "").replace(/[<>&"'`]/g, "").trim().slice(0, 24) : "";
    rooms.set(code, { code, name, mission, count, playing, guest, at: Date.now() });
    res.json({ ok: true });
});
app.delete("/api/rooms/:code", roomLimit, (req, res) => { rooms.delete(String(req.params.code || "").toUpperCase()); res.json({ ok: true }); });

app.get("/", (req, res) => res.send("Space Shooter sync server (Google Drive) is running."));

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Space Shooter sync server listening on port ${PORT}`);
        if (!ADMIN_KEY) console.warn("⚠️  ไม่ได้ตั้ง ADMIN_KEY — คำสั่งแอดมินถูกปิดไว้");
        getPlayersFolderId().then(() => console.log("เชื่อมต่อ Google Drive สำเร็จ")).catch(e => console.error("เชื่อมต่อ Google Drive ไม่สำเร็จ:", e.message));
    });
}
module.exports = app;
