const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Setup Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'mirt-secret-key-12345',
    resave: false,
    saveUninitialized: false
}));

// Setup SQLite Database
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        
        // Create users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`, (err) => {
            if (!err) {
                // Insert default admin if not exists (password: admin123)
                const salt = bcrypt.genSaltSync(10);
                const hash = bcrypt.hashSync('admin123', salt);
                db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, ['admin', hash]);
            }
        });

        // Create posts table
        db.run(`CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            image_url TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// Middleware to protect admin routes
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Routes

// Public: Home page
app.get('/', (req, res) => {
    db.all("SELECT * FROM posts ORDER BY created_at DESC", [], (err, rows) => {
        if (err) {
            console.error(err);
            res.status(500).send("Database error");
            return;
        }
        res.render('index', { posts: rows });
    });
});

// Admin: Login page
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/admin');
    }
    res.render('login', { error: null });
});

// Admin: Login action
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err || !user) {
            return res.render('login', { error: 'Invalid username or password' });
        }
        if (bcrypt.compareSync(password, user.password)) {
            req.session.userId = user.id;
            res.redirect('/admin');
        } else {
            res.render('login', { error: 'Invalid username or password' });
        }
    });
});

// Admin: Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Admin: Dashboard
app.get('/admin', requireAuth, (req, res) => {
    db.all("SELECT * FROM posts ORDER BY created_at DESC", [], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Database error");
        }
        res.render('admin', { posts: rows });
    });
});

// Admin: Add Post Page
app.get('/admin/add', requireAuth, (req, res) => {
    res.render('edit-post', { post: null });
});

// Admin: Add Post Action
app.post('/admin/add', requireAuth, (req, res) => {
    const { title, content, image_url } = req.body;
    db.run(`INSERT INTO posts (title, content, image_url) VALUES (?, ?, ?)`, [title, content, image_url], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database error");
        }
        res.redirect('/admin');
    });
});

// Admin: Edit Post Page
app.get('/admin/edit/:id', requireAuth, (req, res) => {
    db.get("SELECT * FROM posts WHERE id = ?", [req.params.id], (err, row) => {
        if (err || !row) {
            return res.redirect('/admin');
        }
        res.render('edit-post', { post: row });
    });
});

// Admin: Edit Post Action
app.post('/admin/edit/:id', requireAuth, (req, res) => {
    const { title, content, image_url } = req.body;
    db.run(`UPDATE posts SET title = ?, content = ?, image_url = ? WHERE id = ?`, [title, content, image_url, req.params.id], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database error");
        }
        res.redirect('/admin');
    });
});

// Admin: Delete Post
app.post('/admin/delete/:id', requireAuth, (req, res) => {
    db.run(`DELETE FROM posts WHERE id = ?`, [req.params.id], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database error");
        }
        res.redirect('/admin');
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
