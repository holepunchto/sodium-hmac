const sodium = require('sodium-universal')
const b4a = require('b4a')

const sha256 = require('./hash/sha256')
const sha512 = require('./hash/sha512')

module.exports = {
  create,
  sha256,
  sha512
}

function create (hash) {
  const BYTES = hash.BYTES
  const STATEBYTES = hash.STATEBYTES + 2 * hash.BYTES

  function init (state, key) {
    const st = state.subarray(0, hash.STATEBYTES)

    const ipad = b4a.alloc(2 * hash.BYTES)
    const opad = state.subarray(hash.STATEBYTES)

    if (key.length > 2 * hash.BYTES) {
      hash.init(st)
      hash.update(st, key)
      hash.final(st, ipad.subarray(0, hash.BYTES))

      opad.set(ipad)
    } else {
      ipad.set(key)
      opad.set(key)
    }

    bufferByteXor(ipad, 0x36)
    bufferByteXor(opad, 0x5c)

    hash.init(st)
    hash.update(st, ipad)

    return state
  }

  function update (state, data) {
    const st = state.subarray(0, hash.STATEBYTES)
    hash.update(st, data)
  }

  function final (state, out = b4a.alloc(BYTES)) {
    const st = state.subarray(0, hash.STATEBYTES)
    const opad = state.subarray(hash.STATEBYTES)

    hash.final(st, out)

    hash.init(st)
    hash.update(st, opad)
    hash.update(st, out)
    hash.final(st, out)

    sodium.sodium_memzero(opad)

    return out
  }

  function simple (data, key, output = b4a.alloc(BYTES)) {
    const state = b4a.alloc(STATEBYTES)

    init(state, key)
    update(state, data)
    final(state, output.subarray(0, BYTES))

    return output
  }

  return {
    BYTES,
    STATEBYTES,
    init,
    update,
    final,
    simple
  }
}

function bufferByteXor (output, byte) {
  for (let i = 0; i < output.byteLength; i++) {
    output[i] ^= byte
  }

  return output
}
