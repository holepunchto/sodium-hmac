const sodium = require('sodium-universal')

module.exports = {
  init: sodium.crypto_hash_sha256_init,
  update: sodium.crypto_hash_sha256_update,
  final: sodium.crypto_hash_sha256_final,
  BYTES: sodium.crypto_hash_sha256_BYTES,
  STATEBYTES: sodium.crypto_hash_sha256_STATEBYTES
}
