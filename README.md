# hmac

HMAC utility

## Usage

```js
const { HMAC, sha256 } = require('@holepunchto/hmac')

const hmac = new HMAC(sha256)

hmac.init(Buffer.from('key'))
  .update(Buffer.from('some'))
  .update(Buffer.from('more'))
  .update(Buffer.from('data'))

const output = hmac.final()

// or use simple api
const same = HMAC.sha256(b4a.from('somemoredata'), key)
```

## API

#### `const hmac = new HMAC(hash, [key])`

Returns a HMAC object using the given `hash` function. If `key` is provided, `init` will be called in the constructror

Expects `hash` to be an object with:
- `init`
- `update`
- `final`
- `BYTES`
- `STATEBYTES`

`sha256` and `sha512` are exported by default.

Returned API:
- `init`
- `update`
- `final`
- `simple`
- `BYTES`
- `STATEBYTES`

Example usage:
```js
const blake2b = {
  init: sodium.crypto_generichash_init,
  update: sodium.crypto_generichash_update,
  final: sodium.crypto_generichash_final,
  BYTES: sodium.crypto_generichash_BYTES,
  STATEBYTES: sodium.crypto_generichash_STATEBYTES
}

const hmac = new HMAC(blake2b)
```

### `hmac.update(data)`

Hash `data` into the HMAC. `hmac.init()` must be called prior to updating

### `const output = hmac.update([buffer])`

Finlise the HMAC. The result will be written to `buffer` if present

### sha256

Exports an HMAC-compatible SHA256 API.

### sha512

Exports an HMAC-compatible SHA512 API.

## License

Apache-2.0
