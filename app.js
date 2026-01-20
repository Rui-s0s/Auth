import express from "express"
import routes from ""


const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
app.use(express.static('public'));

app.use('/', routes)
app.listen(3000, () => console.log('Server running on http://localhost:3000'))