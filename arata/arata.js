const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');


const app = express();

// Parsing

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// 1. Session Config

app.use(session({
  store: new pgSession({ pool: yourPostgresPool, tableName: 'session' }),
  secret: 'super_secret_session',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: true,        // HTTPS only
    sameSite: 'lax'      // or 'strict'
  } // 30 days
}));

// 2. CSRF Middleware and XSS security, CSP

const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);
app.use(helmet());

// 3. Auth Middleware (Checks both pockets)

const authorize = (req, res, next) => {
  if (req.session.userId) {
    req.user = { id: req.session.userId, username: req.session.username };
    res.locals.authMethod = 'Postgres Session';
    return next();
  }
  
  const token = req.cookies.accessToken;
  if (token) {
    try {
      req.user = jwt.verify(token, 'jwt_secret');
      res.locals.authMethod = 'Stateless JWT';
      return next();
    } catch (e) { res.clearCookie('accessToken'); }
  }
  res.redirect('/login');
};

// 4. Routes

app.get('/login', (req, res) => res.render('login', { csrfToken: req.csrfToken() }));

app.get('/protected', authorize, (req, res) => {
  res.render('protected', { user: req.user, csrfToken: req.csrfToken() });
});

app.post('/login', async (req, res) => {
  const { username, mode } = req.body;
  const user = { id: 1, username }; // example

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
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.cookie('accessToken', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax'
    });

    res.json({ success: true, method: 'jwt' });
  }
});


app.post('/logout', (req, res) => {
  res.clearCookie('accessToken');
  req.session.destroy(() => res.redirect('/login'));
});

// SOMETHING LIKE THIS TO CHECK ADMIN OR NOT

const requireAdmin = async (req, res, next) => {
  const userId = req.user.id; // set earlier by your authorize middleware

  const result = await db.query(
    'SELECT role FROM users WHERE id = $1',
    [userId]
  );

  if (!result.rows.length) return res.sendStatus(403);

  const role = result.rows[0].role;

  if (role !== 'admin') return res.sendStatus(403);

  next();
};

app.listen(3000);

// USE REDIS WITH DOCKER