const sodium = require('sodium-universal')

module.exports = {
  init: sodium.crypto_hash_sha512_init,
  update: sodium.crypto_hash_sha512_update,
  final: sodium.crypto_hash_sha512_final,
  BYTES: sodium.crypto_hash_sha512_BYTES,
  STATEBYTES: sodium.crypto_hash_sha512_STATEBYTES
}
