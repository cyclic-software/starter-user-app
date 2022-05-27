const express = require('express')
const app = express()
const helmet = require('helmet')
const db = require('cyclic-dynamodb')
const auth = require('./auth.js')
const session = require('express-session')
const cookieParser = require('cookie-parser')
const { v4: uuid } = require('uuid')

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
    secure: true,//(process.env.NODE_ENV != 'development'),
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
  index: ['index.html'],
  maxAge: '1m',
  redirect: false
}
app.use(express.static('public', options))

const users = db.collection('users')

app.get('/logout', (req, res) => {
  req.session.destroy()
  res.redirect('/')
})

app.post('/login', async (req, res) => {
  console.log('login called')
  res.redirect('/')
})

app.post('/signup', async (req, res) => {
  console.log(req.body)

  const email = req.body.email
  const psw = req.body.psw
  const psw_repeat = req.body.psw_repeat

  const existingUser = await users.get(email)
  if (existingUser) {
    res.json({ error: 'email already registered' }).end()
    return
  }
  if (psw !== psw_repeat) {
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
  res.setCookie
  res.json(user.props).end()
})

// const petSchema = {
//   id: '/Pet',
//   type: 'object',
//   properties: {
//     gender: {
//       type: 'string',
//       required: true,
//       enum: ['male', 'female']
//     },
//     breed: {
//       type: 'string',
//       required: true
//     }
//   }
// }

// app.post('/:col/:key', validate({ body: petSchema }), async (req, res) => {
//   console.log(req.body)

//   const col = req.params.col
//   const key = req.params.key
//   console.log(`from collection: ${col} delete key: ${key} with params ${JSON.stringify(req.params)}`)
//   const item = await db.collection(col).set(key, req.body)
//   console.log(JSON.stringify(item, null, 2))
//   res.json(item).end()
// })

app.delete('/:col/:key', async (req, res) => {
  const col = req.params.col
  const key = req.params.key
  console.log(`from collection: ${col} delete key: ${key} with params ${JSON.stringify(req.params)}`)
  const item = await db.collection(col).delete(key)
  console.log(JSON.stringify(item, null, 2))
  res.json(item).end()
})

app.get('/:col/:key', async (req, res) => {
  const col = req.params.col
  const key = req.params.key
  console.log(`from collection: ${col} get key: ${key} with params ${JSON.stringify(req.params)}`)
  const item = await db.collection(col).get(key)
  console.log(JSON.stringify(item, null, 2))
  res.json(item).end()
})

app.get('/:col', async (req, res) => {
  const col = req.params.col
  console.log(`list collection: ${col} with params: ${JSON.stringify(req.params)}`)
  const items = await db.collection(col).list()
  console.log(JSON.stringify(items, null, 2))
  res.json(items).end()
})

// Catch all handler for all other request.
app.use('*', (req, res) => {
  res.json({ msg: 'no route handler found', path: req.path, method: req.method }).end()
})

/*
    Setup a general error handler for JsonSchemaValidation errors.
    As mentioned before, how one handles an invalid request depends on their application.
    You can easily create some express error middleware
    (http://expressjs.com/guide/error-handling.html) to customize how your
    application behaves. When the express-jsonschema.validate middleware finds invalid data it
    passes an instance of JsonSchemaValidation to the next middleware.
    Below is an example of a general JsonSchemaValidation error handler for
    an application.
*/
app.use(function (err, req, res, next) {
  let responseData

  if (err.name === 'JsonSchemaValidation') {
    // Log the error however you please
    console.log(err.message)
    // logs "express-jsonschema: Invalid data found"

    // Set a bad request http response status or whatever you want
    res.status(400)

    // Format the response body however you want
    responseData = {
      statusText: 'Bad Request',
      jsonSchemaValidation: true,
      validations: err.validations // All of your validation information
    }

    // Take into account the content type if your app serves various content types
    if (req.xhr || req.get('Content-Type') === 'application/json') {
      res.json(responseData)
    } else {
      // If this is an html request then you should probably have
      // some type of Bad Request html template to respond with
      res.render('badrequestTemplate', responseData)
    }
  } else {
    // pass error to next error middleware handler
    next(err)
  }
})

const port = process.env.PORT || 3000

app.listen(port, () => {
  console.log(`index.js listening on ${port}`)
})
