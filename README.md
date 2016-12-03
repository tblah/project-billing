# project-billing
This project contains some implementations of secure privacy-friendly billing for smart meters. It is build on top of [proj_net](https://github.com/tblah/project-net).

This project is licenced under GPL version 3 or later as published by the [Free Software Foundation](https://fsf.org).

**Please do not use this for anything important. The cryptography in proj_crypto has not been reviewed by a professional.**

Building (you may need to install libsodium first):
```
cargo build
```

Testing:
```
cargo test
```

To generate documentation:
```
cargo doc
```

For documentation of the cryptography see [proj_crypto](https://github.com/tblah/project-crypto).

