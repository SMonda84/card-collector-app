const express = require("express");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const app = express();
const PORT = process.env.PORT || 3000;

// SQLite DB
const db = new sqlite3.Database("./database.db");

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));
app.use(session({ secret: "secret-key", resave: false, saveUninitialized: true }));

app.set("view engine", "ejs");

// Multer (upload immagini)
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, "public/uploads"),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// DB Init
db.run(\`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
\`);
db.run(\`
    CREATE TABLE IF NOT EXISTS cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        type TEXT,
        rarity TEXT,
        image TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
\`);

// Auth middleware
const checkAuth = (req, res, next) => {
    if (!req.session.userId) return res.redirect("/login");
    next();
};

// Routes
app.get("/", (req, res) => res.redirect("/dashboard"));

app.get("/register", (req, res) => res.render("register"));
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], (err) => {
        if (err) return res.send("Username già esistente.");
        res.redirect("/login");
    });
});

app.get("/login", (req, res) => res.render("login"));
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.send("Credenziali non valide");
        }
        req.session.userId = user.id;
        res.redirect("/dashboard");
    });
});

app.get("/dashboard", checkAuth, (req, res) => {
    db.all("SELECT * FROM cards WHERE user_id = ?", [req.session.userId], (err, cards) => {
        res.render("dashboard", { cards });
    });
});

app.get("/add", checkAuth, (req, res) => res.render("add_card"));
app.post("/add", checkAuth, upload.single("image"), (req, res) => {
    const { name, type, rarity } = req.body;
    const image = req.file.filename;
    db.run("INSERT INTO cards (user_id, name, type, rarity, image) VALUES (?, ?, ?, ?, ?)", 
        [req.session.userId, name, type, rarity, image],
        () => res.redirect("/dashboard"));
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login");
});

app.listen(PORT, () => console.log("Server avviato su http://localhost:" + PORT));