import express from "express"
import routes from "./routes/routes.js"
import cors from "cors"
import dotenv from "dotenv"

dotenv.config();

const app = express()

app.use(express.json())
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
// app.use(cors({
//   origin : "http://localhost:3000", 
//   credentials: true // <= Accept credentials (cookies) sent by the client
// }))

app.use('/', routes)
app.listen(3000, () => console.log('Server running on http://localhost:3000'))