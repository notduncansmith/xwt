# xwt

[![GoDoc](https://godoc.org/github.com/notduncansmith/xwt?status.svg)](https://godoc.org/github.com/notduncansmith/xwt) [![Build Status](https://travis-ci.com/notduncansmith/xwt.svg?branch=master)](https://travis-ci.com/notduncansmith/xwt) [![codecov](https://codecov.io/gh/notduncansmith/xwt/branch/master/graph/badge.svg)](https://codecov.io/gh/notduncansmith/xwt)

xwt is a nearly-structureless web token. This repository contains a description of what little structure there is, and a Go library that implements xwt.

## Structure of an xwt

An xwt is a byte sequence with 2 segments. The Data segment contains a version (the current version is 1), an expiry timestamp, and any number of miscellaneous bytes (though it is best to keep this under 1kb). The Signature segment is an Ed25519 signature of the Data section concatenated in that order: `(version|expiry|misc)`. A full xwt is the signature followed by the data: `(signature|version|expiry|misc)`.

```
Example full xwt (Version: 1, ID: "user:12345", Expires: 1583826163): 55df65412fa72f83e439e17e1f62c2fe6c0963114f65e9e1bc0712ec17088291d660229cc875bf697e0a8821d90a7413d7958abc81fa5f8e0164969fa8ef760a763131353833383236313633757365723a3132333435

The same example, but with fields delimited by | : 55df65412fa72f83e439e17e1f62c2fe6c0963114f65e9e1bc0712ec17088291d660229cc875bf697e0a8821d90a7413d7958abc81fa5f8e0164969fa8ef760a | 7631 | 31353833383236313633 | 757365723a3132333435

Signature: 55df65412fa72f83e439e17e1f62c2fe6c0963114f65e9e1bc0712ec17088291d660229cc875bf697e0a8821d90a7413d7958abc81fa5f8e0164969fa8ef760a

Version:
7631

Expires:
31353833383236313633

Misc:
757365723a3132333435
```
