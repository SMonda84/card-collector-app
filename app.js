const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const db = new sqlite3.Database('database.db');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true
}));

// File upload setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = 'public/uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// DB init
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    image TEXT,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// Middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

// Routes
app.get('/', (req, res) => res.redirect('/cards'));

app.get('/register', (req, res) => res.render('register'));
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], err => {
    if (err) return res.send('Errore nella registrazione');
    res.redirect('/login');
  });
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.send('Credenziali non valide');
    }
    req.session.userId = user.id;
    res.redirect('/cards');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/cards', requireLogin, (req, res) => {
  db.all("SELECT * FROM cards WHERE user_id = ?", [req.session.userId], (err, cards) => {
    res.render('cards', { cards });
  });
});

app.get('/cards/new', requireLogin, (req, res) => res.render('new'));
app.post('/cards', requireLogin, upload.single('image'), (req, res) => {
  const { name } = req.body;
  const image = req.file ? '/uploads/' + req.file.filename : null;
  db.run("INSERT INTO cards (name, image, user_id) VALUES (?, ?, ?)", [name, image, req.session.userId], err => {
    res.redirect('/cards');
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server avviato su http://localhost:" + PORT));