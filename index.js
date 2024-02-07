const sodium = require('sodium-universal')
const b4a = require('b4a')

module.exports = function createHmac (hash) {
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

  return {
    BYTES,
    STATEBYTES,
    init,
    update,
    final
  }
}

function bufferByteXor (output, byte) {
  for (let i = 0; i < output.byteLength; i++) {
    output[i] ^= byte
  }

  return output
}
