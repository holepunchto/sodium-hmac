const test = require('brittle')
const b4a = require('b4a')

const vectors = require('./vectors.json')

const { HMAC, sha256, sha512 } = require('../')

test('basic - sha256', t => {
  const hmac = new HMAC(sha256)

  const key = b4a.from('password')
  const input = b4a.from('input')

  const output = b4a.alloc(hmac.length)

  hmac.init(key)
  hmac.update(input)
  hmac.final(output)

  t.unlike(output, b4a.alloc(hmac.length))
  t.alike(output, HMAC.sha256(input, key))
})

test('basic - sha512', t => {
  const hmac = new HMAC(sha512)

  const key = b4a.from('password')
  const input = b4a.from('input')

  const output = b4a.alloc(hmac.length)

  hmac.init(key)
  hmac.update(input)
  hmac.final(output)

  t.unlike(output, b4a.alloc(hmac.length))
  t.alike(output, HMAC.sha512(input, key))
})

test('vectors', t => {
  const hmac256 = new HMAC(sha256)
  const hmac512 = new HMAC(sha512)

  const output256 = b4a.alloc(hmac256.length)
  const output512 = b4a.alloc(hmac512.length)

  for (const { key, data, sha256, sha512 } of vectors) {
    const keyb = b4a.from(key, 'hex')
    const datab = b4a.from(data, 'hex')

    hmac256.init(keyb)
    hmac256.update(datab)
    hmac256.final(output256)

    t.is(b4a.toString(output256, 'hex'), sha256)

    hmac512.init(keyb)
    hmac512.update(datab)
    hmac512.final(output512)

    t.is(b4a.toString(output512, 'hex'), sha512)
  }
})
