const test = require('brittle')
const sodium = require('sodium-universal')
const b4a = require('b4a')

const vectors = require('./vectors.json')

const hmac256 = require('../sha256')
const hmac512 = require('../sha512')

test('basic - sha256', t => {
  const hmac = hmac256

  t.is(hmac.BYTES, sodium.crypto_hash_sha256_BYTES)
  t.is(hmac.STATEBYTES, sodium.crypto_hash_sha256_STATEBYTES + sodium.crypto_hash_sha256_BYTES * 2)

  const key = b4a.from('password')

  const state = b4a.alloc(hmac.STATEBYTES)
  const output = b4a.alloc(hmac.BYTES)

  hmac.init(state, key)
  hmac.update(state, b4a.from('input'))
  hmac.final(state, output)

  t.unlike(output, b4a.alloc(hmac.BYTES))
})

test('basic - sha512', t => {
  const hmac = hmac512

  t.is(hmac.BYTES, sodium.crypto_hash_sha512_BYTES)
  t.is(hmac.STATEBYTES, sodium.crypto_hash_sha512_STATEBYTES + sodium.crypto_hash_sha512_BYTES * 2)

  const key = b4a.from('password')

  const state = b4a.alloc(hmac.STATEBYTES)
  const output = b4a.alloc(hmac.BYTES)

  hmac.init(state, key)
  hmac.update(state, b4a.from('input'))
  hmac.final(state, output)

  t.unlike(output, b4a.alloc(hmac.BYTES))
})

test('vectors', t => {
  const state256 = b4a.alloc(hmac256.STATEBYTES)
  const state512 = b4a.alloc(hmac512.STATEBYTES)

  const output256 = b4a.alloc(hmac256.BYTES)
  const output512 = b4a.alloc(hmac512.BYTES)

  for (const { key, data, sha256, sha512 } of vectors) {
    const keyb = b4a.from(key, 'hex')
    const datab = b4a.from(data, 'hex')

    hmac256.init(state256, keyb)
    hmac256.update(state256, datab)
    hmac256.final(state256, output256)

    t.is(b4a.toString(output256, 'hex'), sha256)

    hmac512.init(state512, keyb)
    hmac512.update(state512, datab)
    hmac512.final(state512, output512)

    t.is(b4a.toString(output512, 'hex'), sha512)
  }
})
