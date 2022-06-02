
const { v4: uuid } = require('uuid')
const crypto = require('crypto')

function securePassword (password) {
  const salt = uuid()
  return { hashed: hashWithSalt(password, salt), salt }
}

function hashWithSalt (password, salt) {
  const hash = crypto.createHmac('sha512', salt)
  hash.update(password)
  const hashed = hash.digest('hex')
  return hashed
}

function testPassword (password, salt, hashed) {
  console.log(password, salt, hashed)
  return password && hashed === hashWithSalt(password, salt)
}

module.exports = {
  securePassword,
  testPassword,
  hashWithSalt
}
