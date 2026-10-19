// ============================================================
// Mahibere Kidusan — Laha Wereda Member Management API (fixed)
// Node.js + Express + better-sqlite3 + JWT auth + Excel export
// ============================================================
try { require('dotenv').config(); } catch (_) { /* dotenv is optional */ }

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const ExcelJS = require('exceljs');
const Database = require('better-sqlite3');

const app = express();
app.set('trust proxy', 1);               // Railway / Render sit behind a proxy
app.use(cors());
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-before-production';
// On Railway/Render, point DB_PATH at a mounted volume (e.g. /data/mk_laha.db) or data is lost on redeploy.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'mk_laha.db');

if (JWT_SECRET === 'change-this-secret-before-production') {
  console.warn('[warn] JWT_SECRET is not set — set it in your environment variables.');
}

// ------------------------------------------------------------
// Database
// ------------------------------------------------------------
let db;
try {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
} catch (e) {
  console.error('[fatal] Could not open the database at', DB_PATH);
  console.error(e);
  process.exit(1);
}

db.exec(`
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  passwordHash TEXT NOT NULL,
  createdAt TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT, firstName TEXT, middleName TEXT, lastName TEXT,
  baptismalName TEXT, motherName TEXT, email TEXT, sex TEXT,
  birthYear TEXT, phone1 TEXT, phone2 TEXT, parishId TEXT,
  emergName TEXT, emergPhone TEXT, emergEmail TEXT, emergRelation TEXT, emergAddress TEXT,
  maritalStatus TEXT, hasChildren TEXT,
  country TEXT, region TEXT, zone TEXT, woreda TEXT, city TEXT, kebele TEXT,
  mkEmployee TEXT, isActive TEXT, monthlyContrib TEXT, monthlyIncome TEXT, notActiveReason TEXT,
  eduLevel TEXT, eduCategory TEXT, eduSubcategory TEXT, currentlyStudying TEXT,
  workStatus TEXT, jobCategory TEXT, workPlace TEXT, orgName TEXT, workResponsibility TEXT, yearsService TEXT,
  hasSpFather TEXT, spFatherName TEXT, spFatherPhone TEXT, spFatherParish TEXT,
  spTitle TEXT, spSchool TEXT, gibigubayae TEXT, gibigubayaeWhere TEXT,
  serviceLevel TEXT, serviceResponsibility TEXT, serviceCenterCurrent TEXT, serviceSubCenter TEXT,
  memberSince TEXT, parishChurch TEXT, parishRole TEXT, serviceDept TEXT, preferredService TEXT,
  execService TEXT, currentAssignment TEXT, otherSkills TEXT, additionalInfo TEXT,
  submittedAt TEXT, createdAt TEXT DEFAULT CURRENT_TIMESTAMP, updatedAt TEXT
);
`);

// Seed a default admin user if none exists yet. CHANGE THE PASSWORD after first login.
const adminCount = db.prepare('SELECT COUNT(*) AS c FROM admin_users').get().c;
if (adminCount === 0) {
  const defaultUser = process.env.ADMIN_USERNAME || 'admin';
  const defaultPass = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
  db.prepare('INSERT INTO admin_users (username, passwordHash) VALUES (?, ?)')
    .run(defaultUser, bcrypt.hashSync(defaultPass, 10));
  console.log(`[seed] Created default admin user "${defaultUser}". CHANGE THIS PASSWORD.`);
}

// Forgot the admin password? Set ADMIN_RESET_PASSWORD (and optionally ADMIN_USERNAME) in your
// environment variables and redeploy: that account's password is reset on startup.
// Remove the variable afterwards.
if (process.env.ADMIN_RESET_PASSWORD) {
  const uname = process.env.ADMIN_USERNAME || 'admin';
  const hash = bcrypt.hashSync(process.env.ADMIN_RESET_PASSWORD, 10);
  const upd = db.prepare('UPDATE admin_users SET passwordHash = ? WHERE username = ?').run(hash, uname);
  if (!upd.changes) db.prepare('INSERT INTO admin_users (username, passwordHash) VALUES (?, ?)').run(uname, hash);
  console.log(`[reset] Password reset for admin "${uname}". Remove ADMIN_RESET_PASSWORD now.`);
}

const MEMBER_FIELDS = [
  'title','firstName','middleName','lastName','baptismalName','motherName','email','sex',
  'birthYear','phone1','phone2','parishId',
  'emergName','emergPhone','emergEmail','emergRelation','emergAddress',
  'maritalStatus','hasChildren',
  'country','region','zone','woreda','city','kebele',
  'mkEmployee','isActive','monthlyContrib','monthlyIncome','notActiveReason',
  'eduLevel','eduCategory','eduSubcategory','currentlyStudying',
  'workStatus','jobCategory','workPlace','orgName','workResponsibility','yearsService',
  'hasSpFather','spFatherName','spFatherPhone','spFatherParish',
  'spTitle','spSchool','gibigubayae','gibigubayaeWhere',
  'serviceLevel','serviceResponsibility','serviceCenterCurrent','serviceSubCenter',
  'memberSince','parishChurch','parishRole','serviceDept','preferredService',
  'execService','currentAssignment','otherSkills','additionalInfo','submittedAt'
];

// ------------------------------------------------------------
// Auth
// ------------------------------------------------------------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(String(username));
  if (!user || !bcrypt.compareSync(String(password), user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, username: user.username });
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || String(newPassword).length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const user = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(req.user.id);
  if (!user || !bcrypt.compareSync(String(currentPassword), user.passwordHash)) {
    return res.status(400).json({ error: 'Current password is incorrect' }); // 400, not 401, so the UI doesn't log out
  }
  db.prepare('UPDATE admin_users SET passwordHash = ? WHERE id = ?')
    .run(bcrypt.hashSync(String(newPassword), 10), user.id);
  res.json({ ok: true });
});

// ------------------------------------------------------------
// Members
// ------------------------------------------------------------
// Public: registration form submission
app.post('/api/members', (req, res) => {
  const data = req.body || {};
  if (!String(data.firstName || '').trim()) return res.status(400).json({ error: 'firstName is required' });
  const placeholders = MEMBER_FIELDS.map(() => '?').join(', ');
  const values = MEMBER_FIELDS.map(c => (data[c] !== undefined && data[c] !== null ? String(data[c]) : ''));
  try {
    const info = db.prepare(`INSERT INTO members (${MEMBER_FIELDS.join(', ')}) VALUES (${placeholders})`).run(...values);
    res.status(201).json({ ok: true, id: Number(info.lastInsertRowid) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to save member' });
  }
});

app.get('/api/members', requireAuth, (req, res) => {
  const search = String(req.query.search || '');
  const sortBy = String(req.query.sortBy || 'id');
  const sortDir = String(req.query.sortDir || 'desc');
  const allowedSort = new Set(['id', 'firstName', 'lastName', 'sex', 'region', 'zone', 'phone1', 'createdAt']);
  const sortCol = allowedSort.has(sortBy) ? sortBy : 'id';
  const dir = sortDir.toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const p = Math.max(parseInt(req.query.page) || 1, 1);
  const l = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 200);

  let where = '';
  let params = [];
  if (search.trim()) {
    where = `WHERE firstName LIKE ? OR middleName LIKE ? OR lastName LIKE ? OR baptismalName LIKE ?
             OR phone1 LIKE ? OR phone2 LIKE ? OR parishId LIKE ? OR email LIKE ? OR parishChurch LIKE ?`;
    params = Array(9).fill(`%${search.trim()}%`);
  }
  const total = db.prepare(`SELECT COUNT(*) AS c FROM members ${where}`).get(...params).c;
  const rows = db.prepare(`SELECT * FROM members ${where} ORDER BY ${sortCol} ${dir} LIMIT ? OFFSET ?`)
    .all(...params, l, (p - 1) * l);
  res.json({ total, page: p, limit: l, totalPages: Math.ceil(total / l), members: rows });
});

app.get('/api/members/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM members WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

// Only the fields that are sent are updated (the old version blanked everything else).
app.put('/api/members/:id', requireAuth, (req, res) => {
  const existing = db.prepare('SELECT id FROM members WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });
  const data = req.body || {};
  const cols = MEMBER_FIELDS.filter(c => data[c] !== undefined && data[c] !== null);
  if (cols.length) {
    db.prepare(`UPDATE members SET ${cols.map(c => `${c} = ?`).join(', ')}, updatedAt = ? WHERE id = ?`)
      .run(...cols.map(c => String(data[c])), new Date().toISOString(), req.params.id);
  }
  res.json({ ok: true });
});

app.delete('/api/members/:id', requireAuth, (req, res) => {
  const info = db.prepare('DELETE FROM members WHERE id = ?').run(req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ------------------------------------------------------------
// Stats
// ------------------------------------------------------------
app.get('/api/stats', requireAuth, (req, res) => {
  const count = (sql) => db.prepare(sql).get().c;
  const group = (col) => db.prepare(
    `SELECT ${col}, COUNT(*) AS count FROM members WHERE ${col} IS NOT NULL AND ${col} != '' GROUP BY ${col} ORDER BY count DESC`
  ).all();

  res.json({
    total: count('SELECT COUNT(*) AS c FROM members'),
    male: count(`SELECT COUNT(*) AS c FROM members WHERE sex LIKE 'ወንድ%'`),
    female: count(`SELECT COUNT(*) AS c FROM members WHERE sex LIKE 'ሴት%'`),
    active: count(`SELECT COUNT(*) AS c FROM members WHERE isActive LIKE 'Yes%'`),
    inactive: count(`SELECT COUNT(*) AS c FROM members WHERE isActive LIKE 'No%'`),
    mkEmployees: count(`SELECT COUNT(*) AS c FROM members WHERE mkEmployee LIKE 'Yes%'`),
    byRegion: group('region'),
    byZone: group('zone'),
    bySubCenter: group('serviceSubCenter'),
    byEduLevel: group('eduLevel'),
    byWorkStatus: group('workStatus'),
    recentSignups: db.prepare('SELECT id, firstName, lastName, createdAt FROM members ORDER BY id DESC LIMIT 5').all()
  });
});

// ------------------------------------------------------------
// Excel export
// ------------------------------------------------------------
app.get('/api/export/excel', requireAuth, async (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM members ORDER BY id ASC').all();
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'Mahibere Kidusan Laha Wereda Member System';
    workbook.created = new Date();

    const sheet = workbook.addWorksheet('Members');
    const columns = ['id', ...MEMBER_FIELDS, 'createdAt', 'updatedAt'];
    sheet.columns = columns.map(c => ({ header: c, key: c, width: 18 }));
    sheet.getRow(1).font = { bold: true };
    sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF5E199' } };
    rows.forEach(r => sheet.addRow(r));
    sheet.views = [{ state: 'frozen', ySplit: 1 }];
    sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };

    const summary = workbook.addWorksheet('Summary');
    summary.addRow(['Mahibere Kidusan Laha Wereda — Member Export Summary']);
    summary.addRow(['Generated', new Date().toISOString()]);
    summary.addRow([]);
    summary.addRow(['Total Members', rows.length]);
    summary.addRow(['Male', rows.filter(r => (r.sex || '').startsWith('ወንድ')).length]);
    summary.addRow(['Female', rows.filter(r => (r.sex || '').startsWith('ሴት')).length]);
    summary.getRow(1).font = { bold: true, size: 14 };

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="mk_laha_members_${Date.now()}.xlsx"`);
    await workbook.xlsx.write(res);
    res.end();
  } catch (e) {
    console.error(e);
    if (!res.headersSent) res.status(500).json({ error: 'Export failed' });
  }
});

// ------------------------------------------------------------
// Health check + serve the web app (index.html)
// ------------------------------------------------------------
app.get('/api/health', (req, res) => res.json({ ok: true }));

const PUBLIC_DIR = path.join(__dirname, 'public');
if (fs.existsSync(PUBLIC_DIR)) app.use(express.static(PUBLIC_DIR));

app.get('/', (req, res) => {
  const candidates = [path.join(PUBLIC_DIR, 'index.html'), path.join(__dirname, 'index.html')];
  const file = candidates.find(f => fs.existsSync(f));
  if (file) return res.sendFile(file);
  res.send('Mahibere Kidusan Laha Wereda API is running. (Put index.html next to server.js or in /public to serve the app.)');
});

// ------------------------------------------------------------
// Error handling
// ------------------------------------------------------------
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`Server listening on port ${PORT}`));
