# hmac

HMAC utility

## Usage

```js
const hmac = require('@holepunchto/hmac/sha256') 

const state = Buffer.alloc(hmac.STATEBYTES) 
const output = Buffer.alloc(hmac.STATEBYTES) 

hmac.init(state, Buffer.from('key'))

hmac.update(state, Buffer.from('some'))
hmac.update(state, Buffer.from('more'))
hmac.update(state, Buffer.from('data'))

hmac.final(state, output)
```

## API

### index.js

index.js exports a single helper for wrapping a hash function with an HMAC API.

#### `createHmac(hash)` 

Returns a HMAC API around the given `hash` function.

Expects `hash` to be an object with:
- `init`
- `update`
- `final`
- `BYTES`
- `STATEBYTES`

Returned API:
- `init`
- `update`
- `final`
- `BYTES`
- `STATEBYTES`

Example usage:
```js
const blakeHmac = createHmac({
  init: sodium.crypto_generichash_init,
  update: sodium.crypto_generichash_update,
  final: sodium.crypto_generichash_final,
  BYTES: sodium.crypto_generichash_BYTES,
  STATEBYTES: sodium.crypto_generichash_STATEBYTES
})
```

### sha256.js

Exports an HMAC-SHA256 API.

### sha512.js

Exports an HMAC-SHA512 API.

## License

MIT