# Keystore JSON v3 offline converter

This tool helps to convert Keystore JSON file from one KDF (key derivation function) to another using [`keythereum`](https://www.npmjs.com/package/keythereum) package.

The converting is only possible for v3 format. The tool helps to convert `scrypt` to `pbkdf2`, and vice versa.

## Usage

```bash
$ npm i
$ env SOURCE=key.json TARGET=newKey.json TARGET_KDF=pbkdf2 TARGET_ROUNDS=10240 PWD_FILENAME=node.pwd npm start
```

Description of the environment parameters:

- `SOURCE` is a filename of the source keystore needed to be converted. Default is `key.json`.
- `TARGET` is a filename of the target keystore needed to be created from the source. Default is `validator.key.0x${address}`.
- `TARGET_KDF` defines KDF which you want to see in the target keystore file. Can be `pbkdf2` or `scrypt`. Default is `pbkdf2`.
- `TARGET_ROUNDS` defines the number of iterations (hashing rounds) needed to decrypt the target keystore. It is a parameter `n` for `scrypt` and parameter `c` for `pbkdf2`. In case of `scrypt` the `TARGET_ROUNDS` must be `2**m, m > 0`. Default is `10240`.
- `PWD_FILENAME` is a filename containing a password for the keystore. Needed to decrypt the source keystore and encrypt the target one. Default is `node.pwd`.

All files must be located in the same directory where `index.js` is located.
