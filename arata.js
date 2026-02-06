require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const helmet = require('helmet')
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;


// const csrfProtection = csrf({
//   cookie: true, // stores secret in cookie
// });

const csrfProtection = csrf({
  cookie: {
    httpOnly: true, // JS cannot read this cookie
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production'
  }
});


const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                  // 5 attempts
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Try again later.',
});

const users = [
  { id: 1, username: '<script>alert("Classic XSS")</script>', passwordHash: bcrypt.hashSync('...', 10) },
  { id: 2, username: '<img src=x onerror=alert("EventXSS")>', passwordHash: bcrypt.hashSync('...', 10) },
  { id: 3, username: '"><script>alert("AttributeBreak")</script>', passwordHash: bcrypt.hashSync('...', 10) },
  { id: 4, username: 'javascript:alert("LinkXSS")', passwordHash: bcrypt.hashSync('...', 10) },
  { id: 5, username: '<svg onload=alert("SVG_XSS")>', passwordHash: bcrypt.hashSync('...', 10) },
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
app.use(helmet())

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

app.post('/login', loginLimiter, async (req, res) => {
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
      sameSite: 'strict'                         
    });
    res.json({ success: true, method: 'jwt' });
  }
});

app.post('/register', csrfProtection, async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Missing required fields');
  }

  // Check if username already exists
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(409).send('Username already exists');
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    username,
    email,
    passwordHash
  };

  users.push(newUser);

  res.redirect('/');
});

app.get('/register', csrfProtection, (req, res) => {
  res.render('register', {
    csrfToken: req.csrfToken()
  });
});

app.post('/logout', csrfProtection, (req, res) => {
  res.clearCookie('accessToken');

  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Logout failed');
    }

    res.clearCookie('connect.sid'); // session cookie (important)
    res.redirect('/');
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



app.get('/dashboard', requireAuth, csrfProtection,  (req, res) => {
  const user = users.find(u => u.id === req.userId);
  res.render('dashboard', {
    username: user?.username || 'Unknown',
    method: req.authMethod,
    csrfToken: req.csrfToken() 
  });
});



// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

