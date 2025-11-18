// index.js
const express = require("express");
const mysql = require("mysql2");
const crypto = require("crypto");
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcrypt");
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  secret: "LEIRA_SECRET_CHANGE_THIS",
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 60 } // 1 jam
}));

// ====== CONFIG DB ======
const db = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "iVoltarouuu13579",
  port: 3309,
  database: "apikey"
});

db.connect(err => {
  if (err) {
    console.error("DB connection error:", err);
    process.exit(1);
  }
  console.log("DB connected");
});

// ====== HELPERS ======
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Not authenticated" });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: "Not authenticated" });
    if (req.session.user.role !== role) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// ====== ROUTES HTML ======
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/user", (req, res) => res.sendFile(path.join(__dirname, "public", "user.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

// ====== API: REGISTER ======
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !password || !email) {
      return res.status(400).json({ error: "username, email, password required" });
    }
    const hashed = await bcrypt.hash(password, 10);
    db.query("INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)",
      [username, email, hashed, role === "admin" ? "admin" : "customer"],
      (err, result) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Username or email exists" });
          console.error(err);
          return res.status(500).json({ error: "DB error" });
        }
        res.json({ success: true, message: "Registered" });
      });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ====== API: LOGIN ======
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username & password required" });

  db.query("SELECT id, username, password, role FROM users WHERE username = ? OR email = ?", [username, username], async (err, rows) => {
    if (err) { console.error(err); return res.status(500).json({ error: "DB error" }); }
    if (!rows || rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    // set session
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ success: true, role: user.role });
  });
});

// ====== API: LOGOUT ======
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ====== API: CREATE/GENERATE API KEY (User only) ======
app.post("/api/createKey", requireLogin, (req, res) => {
  // only customers (but admin could also have keys if you want)
  // here allow customer role only to call from user page
  const userId = req.session.user.id;

  const token = crypto.randomBytes(32).toString("hex");
  const apiKey = "Leira_" + token + "_" + Date.now().toString().slice(-6);

  db.query("INSERT INTO api_key (user_id, KeyValue, status) VALUES (?,?,?)",
    [userId, apiKey, "active"],
    (err, result) => {
      if (err) { console.error(err); return res.status(500).json({ error: "DB error" }); }
      res.json({ success: true, apiKey });
    });
});

// ====== API: SAVE API KEY METADATA (optional) ======
// If you want separate endpoint to mark saved/metadata, you can add later

// ====== API: ADMIN - LIST USERS ======
app.get("/api/admin/users", requireRole("admin"), (req, res) => {
  db.query("SELECT id, username, email, role, created_at FROM users", (err, rows) => {
    if (err) { console.error(err); return res.status(500).json({ error: "DB error" }); }
    res.json({ users: rows });
  });
});

// ====== API: ADMIN - LIST API KEYS ======
app.get("/api/admin/apikeys", requireRole("admin"), (req, res) => {
  db.query(
    `SELECT a.id, a.KeyValue, a.status, a.created_at, u.id AS user_id, u.username, u.email
     FROM api_key a
     LEFT JOIN users u ON a.user_id = u.id
     ORDER BY a.created_at DESC`,
    (err, rows) => {
      if (err) { console.error(err); return res.status(500).json({ error: "DB error" }); }
      res.json({ apikeys: rows });
    });
});

// ====== API: GET CURRENT SESSION INFO ======
app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  res.json({ user: req.session.user });
});

// ====== START ======
app.listen(port, () => console.log(`Server berjalan di http://localhost:${port}`));
