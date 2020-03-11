# xwt

xwt is a nearly-structureless web token. This repository contains a description of what little structure there is, and a Go library that implements xwt.

## Structure of an xwt

An xwt is a byte sequence with 2 segments. The Data segment contains a version (the current version is 1), an expiry timestamp, and any number of miscellaneous bytes (though it is best to keep this under 1kb). The Signature segment is an Ed25519 signature of the Data section concatenated in that order: `(version|expiry|misc)`. A full xwt is the signature followed by the data: `(signature|version|expiry|misc)`.