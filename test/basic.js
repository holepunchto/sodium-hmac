const test = require('brittle')
const sodium = require('sodium-universal')
const b4a = require('b4a')

const vectors = require('./vectors.json')

const { create, sha256, sha512 } = require('../')

test('basic - sha256', t => {
  const hmac = create(sha256)

  t.is(hmac.BYTES, sodium.crypto_hash_sha256_BYTES)
  t.is(hmac.STATEBYTES, sodium.crypto_hash_sha256_STATEBYTES + sodium.crypto_hash_sha256_BYTES * 2)

  const key = b4a.from('password')
  const input = b4a.from('input')

  const state = b4a.alloc(hmac.STATEBYTES)
  const output = b4a.alloc(hmac.BYTES)

  hmac.init(state, key)
  hmac.update(state, input)
  hmac.final(state, output)

  t.unlike(output, b4a.alloc(hmac.BYTES))
  t.alike(output, hmac.simple(input, key))
})

test('basic - sha512', t => {
  const hmac = create(sha512)

  t.is(hmac.BYTES, sodium.crypto_hash_sha512_BYTES)
  t.is(hmac.STATEBYTES, sodium.crypto_hash_sha512_STATEBYTES + sodium.crypto_hash_sha512_BYTES * 2)

  const key = b4a.from('password')
  const input = b4a.from('input')

  const state = b4a.alloc(hmac.STATEBYTES)
  const output = b4a.alloc(hmac.BYTES)

  hmac.init(state, key)
  hmac.update(state, input)
  hmac.final(state, output)

  t.unlike(output, b4a.alloc(hmac.BYTES))
  t.alike(output, hmac.simple(input, key))
})

test('vectors', t => {
  const hmac256 = create(sha256)
  const hmac512 = create(sha512)

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
