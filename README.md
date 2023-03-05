# Blockchain Hashing ("bc_hash")

*bc_hash* is a Rust library of cryptographic hashing algorithms commonly used in blockchain applications. It is designed to be as flexible and easy to use as possible. Key features include:

- Methods for calculating a new hash from a String, Vector, File, or Path.
- Robust error handling
- Implementations for many of Rust's commonly used traits such as From/TryFrom, Display, PartialEq/Eq, Default, etc.
- Native methods to serialize and deserialize a SHA-256 digest to and from a slice of bytes.

At the moment, only the SHA-256 has been implemented. However, more algorithms are planning for implementation in the future.

## License

*bc_hash* is licensed under the MIT License.

## Dependancies

None :-)

## Resources

The following are suggested resources for anyone interested in learning more about the SHA-256 algorithm:

* https://sha256algorithm.com/
* https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
* https://medium.com/a-42-journey/implementing-the-sha256-and-md5-hash-functions-in-c-78c17e657794
* https://github.com/ilvn/SHA256

## Documentation

[Click here to view the documentation](https://github.com/herrsmitty8128/bc_hash/docs/index.html)
