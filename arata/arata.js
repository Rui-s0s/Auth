require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');


const app = express();
const PORT = 3000;

// Fake user database
// const users = [
//   { id: 1, username: 'alice', passwordHash: bcrypt.hashSync('pass123', 10) },
//   { id: 2, username: 'bob', passwordHash: bcrypt.hashSync('secret', 10) },
//   { id: 3, username: '<script>alert(1)</script>', passwordHash: bcrypt.hashSync('quilo', 10) }
// ];

const users = [
  // 1. Basic Script Tag (The Classic)
  { id: 1, username: '<script>alert("Classic XSS")</script>', passwordHash: bcrypt.hashSync('...', 10) },

  // 2. Image Event Handler (Sneaks past simple <script> filters)
  { id: 2, username: '<img src=x onerror=alert("EventXSS")>', passwordHash: bcrypt.hashSync('...', 10) },

  // 3. Attribute Breakout (Tests if you're escaping quotes in HTML attributes)
  // Target: <input value="{{username}}"> 
  { id: 3, username: '"><script>alert("AttributeBreak")</script>', passwordHash: bcrypt.hashSync('...', 10) },

  // 4. Anchor Tag/Pseudo-protocol (Tests "href" or "src" links)
  // Target: <a href="{{username}}">Profile</a>
  { id: 4, username: 'javascript:alert("LinkXSS")', passwordHash: bcrypt.hashSync('...', 10) },

  // 5. SVG Payload (Often overlooked by sanitizers)
  { id: 5, username: '<svg onload=alert("SVG_XSS")>', passwordHash: bcrypt.hashSync('...', 10) },

  // 6. Style-based Injection (Targeting CSS contexts)
  { id: 6, username: '<div style="width: expression(alert(\'IE_XSS\'));">', passwordHash: bcrypt.hashSync('...', 10) }
];


// PostgreSQL pool (needed if you want session storage in DB)
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'auth',
  password: 'penguin',
  port: 5432
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // serve /public
app.use(cookieParser());

// CSP header
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; connect-src 'self'; style-src 'self';"
  );
  next();
});

// Session middleware
app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'keyboardcat',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password, mode } = req.body;
  console.log(username)

  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  if (mode === 'session') {
    req.session.regenerate(err => {
      if (err) return res.sendStatus(500);

      req.session.userId = user.id;
      req.session.username = user.username;
      res.json({ success: true, method: 'session' });
    });
  } else {
    const token = jwt.sign(
      { uid: user.id },
      process.env.JWT_SECRET || 'jwtsecret',
      { expiresIn: '15m' }
    );
    res.cookie('accessToken', token, {
      httpOnly: true,
      secure: false, 
      sameSite: 'strict'                          // Maybe strict
    });
    res.json({ success: true, method: 'jwt' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('accessToken');

  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Logout failed');
    }

    res.clearCookie('connect.sid'); // session cookie (important)
    res.redirect('/login');
  });
});


function requireAuth(req, res, next) {

  console.log(req.cookies)
  console.log(req.cookie)

  // 1️⃣ Check session
  if (req.session && req.session.userId) {
    req.userId = req.session.userId;
    req.authMethod = 'session';
    return next();
  }

  // 2️⃣ Check JWT
  const token = req.cookies?.accessToken;
  if (token) {
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET || 'jwtsecret');
      req.userId = payload.uid;
      req.authMethod = 'jwt';
      return next();
    } catch (err) {
      // Invalid or expired token → continue to fail
    }
  }

  // 3️⃣ Not authenticated
  return res.status(401).json({ error: 'Unauthorized: login required' });
}



app.get('/dashboard', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  res.render('dashboard', {
    username: user?.username || 'Unknown',
    method: req.authMethod
  });
});



// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

