import express from "express"
import routes from "./routes/routes.js"
import dotenv from "dotenv"
import session from "express-session"
import jwt from "jsonwebtoken"
import csurf from "csurf"
import helmet from "helmet"
import rateLimit from "express-rate-limit";


const loginLimiter = rateLimit({
windowMs: 15 * 60 * 1000, // 15 minutes
max: 10, // max 10 attempts
message: "Too many login attempts. Try later."
});


app.post("/auth/login", loginLimiter, loginHandler);

dotenv.config();

const app = express()

app.use(express.json())
app.use(session({
secret: process.env.SESSION_SECRET,
resave: false,
saveUninitialized: false,
cookie: { httpOnly: true, secure: true }
}));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }))
app.use(helment())
app.set('view engine', 'ejs')


app.use('/', routes)
app.listen(3000, () => console.log('Server running on http://localhost:3000'))