const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./db');

const app = express();
app.use(express.json());

// เสิร์ฟไฟล์ Frontend (HTML, CSS, JS) จากโฟลเดอร์ public
app.use(express.static(path.join(__dirname, 'public')));

const SECRET_KEY = 'super_secret_key_for_jwt';

// --- AUTH API ---
app.post('/api/register', async (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password) return res.status(400).json({ error: "กรุณากรอกข้อมูลให้ครบถ้วน" });
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  db.run(`INSERT INTO Users (name, phone, password) VALUES (?, ?, ?)`, 
    [name, phone, hashedPassword], 
    function(err) {
      if (err) return res.status(400).json({ error: "เบอร์โทรศัพท์นี้ถูกใช้งานแล้ว" });
      res.json({ message: "สมัครสมาชิกสำเร็จ", userId: this.lastID });
  });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  db.get(`SELECT * FROM Users WHERE phone = ?`, [phone], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง" });
    }
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET_KEY, { expiresIn: '1d' });
    res.json({ message: "เข้าสู่ระบบสำเร็จ", token: token, role: user.role, name: user.name });
  });
});

// --- MIDDLEWARE ---
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: "กรุณาเข้าสู่ระบบ" });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Token ไม่ถูกต้องหรือหมดอายุ" });
    req.user = decoded; 
    next();
  });
};

const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: "ปฏิเสธการเข้าถึง: คุณไม่ใช่ Admin" });
    }
    next();
  });
};

// --- REPORT API ---
app.post('/api/reports', requireAuth, (req, res) => {
  const { suspect_name, bank_account, damage_amount, details } = req.body;
  db.run(`INSERT INTO Reports (user_id, suspect_name, bank_account, damage_amount, details) VALUES (?, ?, ?, ?, ?)`,
    [req.user.id, suspect_name, bank_account, damage_amount, details],
    function(err) {
      if (err) return res.status(500).json({ error: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" });
      res.json({ message: "แจ้งเบาะแสสำเร็จ", reportId: this.lastID });
    }
  );
});

app.get('/api/reports/search', (req, res) => {
  const { q } = req.query;
  const query = q ? `%${q}%` : '%';
  db.all(`SELECT suspect_name, bank_account, details, status FROM Reports WHERE suspect_name LIKE ? OR bank_account LIKE ?`, 
    [query, query], (err, rows) => {
      if (err) return res.status(500).json({ error: "เกิดข้อผิดพลาด" });
      res.json(rows);
  });
});

// --- ADMIN API ---
app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all(`SELECT id, name, phone, role FROM Users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "เกิดข้อผิดพลาด" });
    res.json(rows);
  });
});

app.patch('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const targetUserId = req.params.id;
  const { newRole } = req.body; 

  if (targetUserId == req.user.id) {
    return res.status(400).json({ error: "ไม่สามารถเปลี่ยนสิทธิ์ของตนเองได้" });
  }

  db.run(`UPDATE Users SET role = ? WHERE id = ?`, [newRole, targetUserId], function(err) {
    if (err) return res.status(500).json({ error: "เกิดข้อผิดพลาดในฐานข้อมูล" });
    if (this.changes === 0) return res.status(404).json({ error: "ไม่พบผู้ใช้งานนี้" });
    res.json({ message: `อัปเดตสิทธิ์ผู้ใช้สำเร็จ` });
  });
});

// ส่งหน้า index.html เป็นค่าเริ่มต้น
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(3000, () => console.log('เซิร์ฟเวอร์รันอยู่ที่ http://localhost:3000'));
