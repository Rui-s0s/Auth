import express from 'express';
import jwt from 'jsonwebtoken';
import session from 'express-session';
import helmet from 'helmet';
let posts = []
const SECRET = 'supersecretkey';
const users = {
    alice: 'password123',
    bob: 'qwerty'
};
// const users = {
//                 alice: { password: 'password123', email:'emaila', role:'admin' },
//                 bob: { password: 'qwerty', email:'emailb', role:'user' }
//               }

const app = express();
app.use(express.json())
app.use(session({
    secret: 'anothersecretkey', // can be any random string
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // true if using HTTPS
        sameSite: 'lax',
        maxAge: 10 * 60 * 1000 // 10 minutes
        }
    }));
app.use(helmet())
app.use(express.static('public'))
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')

function authMiddleware(req, res, next) {
    console.log('req.body:', req.body); // will be undefined on GET
    console.log('Authorization header:', req.headers.authorization);
  // JWT check
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const payload = jwt.verify(token, SECRET);
      req.user = { type: 'jwt', username: payload.sub };
      return next();
    } catch {}
  }

  // Session check
  if (req.session?.user) {
    req.user = { type: 'session', username: req.session.user };
    return next();
  }

  return res.status(401).json({ error: 'Not authenticated' });
}

app.get('/protected', authMiddleware, (req, res) => {
  res.render('protect');
});

app.get('/login', (req, res) => {
    res.render('login')
})

app.get('/register', (req, res) => {
    res.render('register')
})

// app.get('/admin', authMiddleware, requireRole('admin'), (req, res) => {
//   res.render('admin', { user: req.user });
// });

app.get('/crud', authMiddleware, (req, res) => {
    res.render('crud', {post})
})


app.post('/login', (req, res) => {
  const { username, password, mode } = req.body;
  if (!users[username] || users[username] !== password)
    return res.status(401).json({ error: 'Invalid credentials' });

  if (mode === 'jwt') {
    const token = jwt.sign({ sub: username }, SECRET, { expiresIn: '5m' });
    return res.json({ accessToken: token });
  }

  if (mode === 'session') {
    req.session.user = username;
    return res.json({ message: 'Logged in with session' });
  }

  res.status(400).json({ error: 'Invalid mode' });
});

app.post('/logout', (req, res) => {
  req.session?.destroy?.(() => {});
  window.accessToken = null;
  res.json({ message: 'Logged out' });
});

app.get('/protected-data', authMiddleware, (req, res) => {
    console.log(`${req.body}
        ${req.headers}`)
  res.json({
    username: req.user.username,
    authType: req.user.type
  });
});

app.listen(8888, () => {
    console.log("server running on http://localhost:8888")
})