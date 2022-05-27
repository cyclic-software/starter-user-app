const express = require('express')
const app = express()
const helmet = require('helmet')
const db = require('cyclic-dynamodb')
const auth = require('./auth.js')
const session = require('express-session')
const cookieParser = require('cookie-parser')
const { v4: uuid } = require('uuid')
const path = require('path')

// const validate = require('express-jsonschema').validate
const oneDayMs = 24 * 60 * 60 * 1000

app.use(helmet())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(session({
  secret: process.env.SESSION_SECRET || uuid(),
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true, // (process.env.NODE_ENV != 'development'),
    maxAge: oneDayMs
  }
}))

// #############################################################################
// This configures static hosting for files in /public that have the extensions
// listed in the array.
const options = {
  dotfiles: 'ignore',
  etag: false,
  extensions: ['htm', 'html', 'css', 'js', 'ico', 'jpg', 'jpeg', 'png', 'svg'],
  // index: ['index.html'],
  maxAge: '1m',
  redirect: false
}
app.use(express.static('public', options))

const users = db.collection('users')

app.get('/logout', (req, res) => {
  req.session.destroy()
  res.redirect('/')
})

app.get('/login', async (req, res) => {
  if (req.session?.logged_in) {
    res.json({ msg: 'You are already logged in.' })
  } else {
    res.sendFile(path.resolve('public/login.html'))
  }
})
app.post('/login', async (req, res) => {
  console.log('login called')

  const email = req.body.email
  const psw = req.body.psw

  const userItem = await users.get(email)
  const user = userItem?.props
  console.log(user)
  if (!user) {
    res.json({ error: 'try again' }).end()
  } else if (auth.testPassword(psw, user.salt, user.hashedPassword)) {
    req.session.logged_in = true
    req.session.user = user
    res.sendFile(path.resolve('public/app.html')).end()
  } else {
    res.json({ error: 'try again' }).end()
  }
})

app.post('/signup', async (req, res) => {
  console.log(req.body)

  const email = req.body.email
  const psw = req.body.psw
  const pswRepeat = req.body.psw_repeat

  const existingUser = await users.get(email)
  if (existingUser) {
    res.json({ error: 'email already registered' }).end()
    return
  }
  if (psw !== pswRepeat) {
    res.json({ error: "passwords don't match" }).end()
    return
  }

  const { salt, hashed } = auth.securePassword(psw)

  const uid = 'uid_' + Math.random().toString().slice(2)
  const uProps = {
    uid,
    email,
    status: 'new',
    salt,
    hashedPassword: hashed
  }

  const user = await users.set(email, uProps, { $index: ['uid'] })

  // console.log(JSON.stringify(user, null, 2))

  delete user.props.salt
  delete user.props.hashedPassword

  // console.log(JSON.stringify(user.props, null, 2))
  res.json(user.props).end()
})

app.get('/', async (req, res) => {
  if (req.session?.logged_in) {
    res.sendFile(path.resolve('public/app.html')).end()
  } else {
    res.sendFile(path.resolve('public/login.html'))
  }
})

// Catch all handler for all other request.
app.use('*', (req, res) => {
  res.json({ msg: 'no route handler found', path: req.path, method: req.method }).end()
})

const port = process.env.PORT || 3000

app.listen(port, () => {
  console.log(`index.js listening on ${port}`)
})
