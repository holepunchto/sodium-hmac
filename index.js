const b4a = require('b4a')

const sha256 = require('./hash/sha256')
const sha512 = require('./hash/sha512')

class HMAC {
  constructor (hash, key) {
    this.hash = hash
    this.length = hash.BYTES

    this._blocksize = 2 * hash.BYTES

    this._initialised = false

    this.state = b4a.alloc(hash.STATEBYTES)
    this.pad = b4a.alloc(this._blocksize)

    if (key) this.init(key)
  }

  init (key) {
    if (this._initialised) {
      throw new Error('Already initialised, call final first')
    }

    if (key.length > this._blocksize) {
      this.hash.init(this.state)
      this.hash.update(this.state, key)
      this.hash.final(this.state, this.pad.subarray(0, this.length))
    } else {
      this.pad.set(key)
    }

    bufferByteXor(this.pad, 0x36)

    this.hash.init(this.state)
    this.hash.update(this.state, this.pad)

    bufferByteXor(this.pad, 0x5c ^ 0x36)

    this._initialised = true

    return this
  }

  update (data) {
    if (!this._initialised) {
      throw new Error('First initialise with a key')
    }

    this.hash.update(this.state, data)
    return this
  }

  final (output = b4a.alloc(this.length)) {
    if (!this._initialised) {
      throw new Error('First initialise with a key')
    }

    const out = output.byteLength === this.length
      ? output
      : output.subarray(0, this.hash.BYTES)

    this.hash.final(this.state, out)

    this.hash.init(this.state)
    this.hash.update(this.state, this.pad)
    this.hash.update(this.state, out)
    this.hash.final(this.state, out)

    this.pad.fill(0)
    this.state.fill(0)

    this._initialised = false

    return out
  }

  static sha256 (data, key, output) {
    const hmac = new HMAC(sha256, key)
    return hmac.update(data).final(output)
  }

  static sha512 (data, key, output) {
    const hmac = new HMAC(sha512, key)
    return hmac.update(data).final(output)
  }
}

module.exports = {
  HMAC,
  sha256,
  sha512
}

function bufferByteXor (output, byte) {
  for (let i = 0; i < output.byteLength; i++) {
    output[i] ^= byte
  }

  return output
}
