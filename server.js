// ============================================================
// Mahibere Kidusan — Laha Wereda Member Management API
// Node.js + Express + better-sqlite3 + JWT auth + Excel export
// ============================================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const ExcelJS = require('exceljs');
const Database = require('better-sqlite3');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-before-production';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'mk_laha.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ------------------------------------------------------------
// Schema
// ------------------------------------------------------------
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

// Seed a default admin user if none exists yet.
// IMPORTANT: change this password immediately after first login.
const adminCount = db.prepare('SELECT COUNT(*) AS c FROM admin_users').get().c;
if (adminCount === 0) {
  const defaultUser = process.env.ADMIN_USERNAME || 'admin';
  const defaultPass = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
  const hash = bcrypt.hashSync(defaultPass, 10);
  db.prepare('INSERT INTO admin_users (username, passwordHash) VALUES (?, ?)').run(defaultUser, hash);
  console.log(`[seed] Created default admin user "${defaultUser}". CHANGE THIS PASSWORD.`);
}

// All member field columns (used for insert/update/export, in display order)
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
// Auth helpers
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
  const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, username: user.username });
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const user = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.passwordHash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE admin_users SET passwordHash = ? WHERE id = ?').run(hash, user.id);
  res.json({ ok: true });
});

// ------------------------------------------------------------
// Public: member registration submission (used by the registration form)
// ------------------------------------------------------------
app.post('/api/members', (req, res) => {
  const data = req.body || {};
  const cols = MEMBER_FIELDS;
  const placeholders = cols.map(() => '?').join(', ');
  const values = cols.map(c => (data[c] !== undefined ? String(data[c]) : ''));
  try {
    const stmt = db.prepare(`INSERT INTO members (${cols.join(', ')}) VALUES (${placeholders})`);
    const info = stmt.run(...values);
    res.status(201).json({ ok: true, id: info.lastInsertRowid });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to save member' });
  }
});

// ------------------------------------------------------------
// Protected: list + search + paginate
// GET /api/members?search=...&page=1&limit=20&sortBy=lastName&sortDir=asc
// ------------------------------------------------------------
app.get('/api/members', requireAuth, (req, res) => {
  const { search = '', page = '1', limit = '20', sortBy = 'id', sortDir = 'desc' } = req.query;
  const allowedSort = new Set(['id', 'firstName', 'lastName', 'sex', 'region', 'zone', 'phone1', 'createdAt']);
  const sortCol = allowedSort.has(sortBy) ? sortBy : 'id';
  const dir = sortDir.toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const p = Math.max(parseInt(page) || 1, 1);
  const l = Math.min(Math.max(parseInt(limit) || 20, 1), 200);
  const offset = (p - 1) * l;

  let where = '';
  let params = [];
  if (search.trim()) {
    where = `WHERE firstName LIKE ? OR middleName LIKE ? OR lastName LIKE ? OR baptismalName LIKE ?
             OR phone1 LIKE ? OR phone2 LIKE ? OR parishId LIKE ? OR email LIKE ? OR parishChurch LIKE ?`;
    const term = `%${search.trim()}%`;
    params = Array(9).fill(term);
  }

  const total = db.prepare(`SELECT COUNT(*) AS c FROM members ${where}`).get(...params).c;
  const rows = db.prepare(
    `SELECT * FROM members ${where} ORDER BY ${sortCol} ${dir} LIMIT ? OFFSET ?`
  ).all(...params, l, offset);

  res.json({ total, page: p, limit: l, totalPages: Math.ceil(total / l), members: rows });
});

app.get('/api/members/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM members WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

app.put('/api/members/:id', requireAuth, (req, res) => {
  const existing = db.prepare('SELECT id FROM members WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });
  const data = req.body || {};
  const setClause = MEMBER_FIELDS.map(c => `${c} = ?`).join(', ');
  const values = MEMBER_FIELDS.map(c => (data[c] !== undefined ? String(data[c]) : ''));
  db.prepare(`UPDATE members SET ${setClause}, updatedAt = ? WHERE id = ?`)
    .run(...values, new Date().toISOString(), req.params.id);
  res.json({ ok: true });
});

app.delete('/api/members/:id', requireAuth, (req, res) => {
  const info = db.prepare('DELETE FROM members WHERE id = ?').run(req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ------------------------------------------------------------
// Protected: statistics
// ------------------------------------------------------------
app.get('/api/stats', requireAuth, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) AS c FROM members').get().c;
  const male = db.prepare(`SELECT COUNT(*) AS c FROM members WHERE sex LIKE 'ወንድ%'`).get().c;
  const female = db.prepare(`SELECT COUNT(*) AS c FROM members WHERE sex LIKE 'ሴት%'`).get().c;
  const active = db.prepare(`SELECT COUNT(*) AS c FROM members WHERE isActive LIKE 'Yes%'`).get().c;
  const inactive = db.prepare(`SELECT COUNT(*) AS c FROM members WHERE isActive LIKE 'No%'`).get().c;
  const mkEmployees = db.prepare(`SELECT COUNT(*) AS c FROM members WHERE mkEmployee LIKE 'Yes%'`).get().c;

  const byRegion = db.prepare(
    `SELECT region, COUNT(*) AS count FROM members WHERE region != '' GROUP BY region ORDER BY count DESC`
  ).all();
  const byZone = db.prepare(
    `SELECT zone, COUNT(*) AS count FROM members WHERE zone != '' GROUP BY zone ORDER BY count DESC`
  ).all();
  const bySubCenter = db.prepare(
    `SELECT serviceSubCenter, COUNT(*) AS count FROM members WHERE serviceSubCenter != '' GROUP BY serviceSubCenter ORDER BY count DESC`
  ).all();
  const byEduLevel = db.prepare(
    `SELECT eduLevel, COUNT(*) AS count FROM members WHERE eduLevel != '' GROUP BY eduLevel ORDER BY count DESC`
  ).all();
  const byWorkStatus = db.prepare(
    `SELECT workStatus, COUNT(*) AS count FROM members WHERE workStatus != '' GROUP BY workStatus ORDER BY count DESC`
  ).all();

  const recentSignups = db.prepare(
    `SELECT id, firstName, lastName, createdAt FROM members ORDER BY createdAt DESC LIMIT 5`
  ).all();

  res.json({
    total, male, female, active, inactive, mkEmployees,
    byRegion, byZone, bySubCenter, byEduLevel, byWorkStatus, recentSignups
  });
});

// ------------------------------------------------------------
// Protected: Excel export
// ------------------------------------------------------------
app.get('/api/export/excel', requireAuth, async (req, res) => {
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
  sheet.autoFilter = { from: 'A1', to: `${String.fromCharCode(64 + Math.min(columns.length, 26))}1` };

  // Summary sheet
  const summarySheet = workbook.addWorksheet('Summary');
  const male = rows.filter(r => (r.sex || '').startsWith('ወንድ')).length;
  const female = rows.filter(r => (r.sex || '').startsWith('ሴት')).length;
  summarySheet.addRow(['Mahibere Kidusan Laha Wereda — Member Export Summary']);
  summarySheet.addRow(['Generated', new Date().toLocaleString()]);
  summarySheet.addRow([]);
  summarySheet.addRow(['Total Members', rows.length]);
  summarySheet.addRow(['Male', male]);
  summarySheet.addRow(['Female', female]);
  summarySheet.getRow(1).font = { bold: true, size: 14 };

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="mk_laha_members_${Date.now()}.xlsx"`);
  await workbook.xlsx.write(res);
  res.end();
});

// ------------------------------------------------------------
app.get('/', (req, res) => res.send('Mahibere Kidusan Laha Wereda API is running.'));

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
