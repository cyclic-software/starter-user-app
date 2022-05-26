const auth = require('../src/auth.js')

describe('auth.test.js', () => {
  test('securePassword is different on different calls', async () => {
    const pw1 = auth.securePassword('password')
    const pw2 = auth.securePassword('password')
    expect(pw1.hashed).not.toEqual(pw2.hashed)
    expect(pw1.salt).not.toEqual(pw2.salt)
  })

  const passwordsToTry = [
    'password',
    '!@#$!%@^&$*(%^*$%$##!@%^&%%#$@#@:{L<>"A?DF>G<:FADLS{C:AWE">:<'
  ]
  test('securePassword returns values that can be tested', async () => {
    passwordsToTry.forEach((pw) => {
      const { salt, hashed } = auth.securePassword(pw)
      expect(auth.hashWithSalt(pw, salt)).toEqual(hashed)
      expect(auth.testPassword(pw, salt, hashed)).toEqual(true)
    })
  })
})
