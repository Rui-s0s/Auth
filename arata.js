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
const userRG = /^[a-zA-Z0-9._%+-]+$/
const emailRG = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+$/

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production'
  }
});

const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5,                  // 5 attempts
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Try again later.',
});

const users = [
  { id: 1, username: '<script>alert("Classic XSS")</script>', passwordHash: bcrypt.hashSync('...', 10), role: 'admin' },
  { id: 2, username: '<img src=x onerror=alert("EventXSS")>', passwordHash: bcrypt.hashSync('...', 10), role: 'admin' },
  { id: 3, username: '"><script>alert("AttributeBreak")</script>', passwordHash: bcrypt.hashSync('...', 10), role: 'admin' },
  { id: 4, username: 'javascript:alert("LinkXSS")', passwordHash: bcrypt.hashSync('...', 10), role: 'admin' },
  { id: 5, username: '<svg onload=alert("SVG_XSS")>', passwordHash: bcrypt.hashSync('...', 10), role: 'admin' },
  { id: 6, username: '<div style="width: expression(alert(\'IE_XSS\'));">', passwordHash: bcrypt.hashSync('...', 10), role: 'admin' }
];


// PostgreSQL pool (needed if you want session storage in DB)
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'auth',
  password: 'addressme',
  port: 5432
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // serve /public
app.use(cookieParser());
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'"],
        styleSrc: ["'self'"],
      },
    },
  })
);

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

function validateInput(req, res, next) {
  let {username, email} = req.body
  if (!userRG.test(username) || !emailRG.test(email)){
    return res.json({error: "Invalid input"})
  }

  next()
}

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

app.post('/register', csrfProtection, validateInput, async (req, res) => {
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
    passwordHash,
    role: 'user'
  };

  users.push(newUser);

  console.table(users)

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

// MIDDLEWARE THAT VERIFIES BOTH ROLE AND AUTH
function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    let user;

    // Session auth
    if (req.session && req.session.userId) {
      user = users.find(u => u.id === req.session.userId);
      if (!user) return res.status(401).json({ error: 'Invalid session' });

    // JWT auth
    } else if (req.cookies && req.cookies.accessToken) {
      try {
        const payload = jwt.verify(
          req.cookies.accessToken,
          process.env.JWT_SECRET || 'jwtsecret'
        );
        user = users.find(u => u.id === payload.uid);
        if (!user) return res.status(401).json({ error: 'Invalid token' });
      } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }

    } else {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check role
    if (allowedRoles.length && !allowedRoles.includes(user.role)) {
      return res.status(403).json({ error: 'Forbidden: insufficient role' });
    }

    // Attach user object for downstream routes
    req.user = user;
    next();
  };
}



app.get('/dashboard', requireRole(['user', 'admin']), csrfProtection, (req, res) => {
  res.render('dashboard', {
    user: req.user,
    csrfToken: req.csrfToken()
  });
});

app.get('/admin', requireRole(['admin']), csrfProtection, (req, res) => {
  // Only send what’s safe (e.g., no password hashes!)
  const safeUsers = users.map(u => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role
  }));

  res.render('admin', {
    user: req.user,       // logged-in admin
    users: safeUsers,     // list of users for the template
    csrfToken: req.csrfToken()
  });
});


// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

