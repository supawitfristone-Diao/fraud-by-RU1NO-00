const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./fraud_prevention.sqlite');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'member'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS Reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    suspect_name TEXT NOT NULL,
    bank_account TEXT,
    damage_amount REAL,
    details TEXT,
    status TEXT DEFAULT 'รอตรวจสอบ',
    FOREIGN KEY(user_id) REFERENCES Users(id)
  )`);
});

module.exports = db;
