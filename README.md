# SYNOPSIS 
[![NPM Package](https://img.shields.io/npm/v/vss.svg?style=flat-square)](https://www.npmjs.org/package/vss)
[![Build Status](https://img.shields.io/travis/wanderer/vss.svg?branch=master&style=flat-square)](https://travis-ci.org/wanderer/vss)
[![Coverage Status](https://img.shields.io/coveralls/wanderer/vss.svg?style=flat-square)](https://coveralls.io/r/wanderer/vss)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)  

This implements [verifiable secret sharing](https://en.wikipedia.org/wiki/Verifiable_secret_sharing) on top of [bls-lib](https://github.com/wanderer/bls-lib/).
Its is based on [Shamir's scheme](https://en.wikipedia.org/wiki/Secret_sharing#Shamir.27s_scheme) but has the added benift that ths recipients can verify their shares against a verifcation vector. 
This insures that dealer cannot hand out invalid shares.

# INSTALL
`npm install vss`

# USAGE

```javascript
const vss = require(']]vss')
const bls = require('bls-lib')

bls.onModuleInit(() => {
  bls.init()
  const threshold = 5
  const numOfPlayers = 7
  const setup = vss.createShare(bls, numOfPlayers, threshold)
  
  // use `setup.secret` to encrypt something, it is a random 32 byte Uint8Array
  // post `setup.verificationVector` somewhere public
  // then send each share in `setup.shares` to someone

  // when the recipients recieve thier share they can verify that it was created
  // corectly with the verifcationVector
  setup.shares.forEach(share => {
    const verified = vss.verifyShare(bls, share, setup.verifcationVector)
    console.log(verified)
  })

  // when `threshold` number of recipients combine their shares the secert key
  // can be recovered
  const secret = vss.recoverSecret(bls, setup.shares.slice(0, threshold))
  // secret === setup.secret
})
```

# API
[./docs/](./docs/index.md)

# LICENSE
[MPL-2.0](https://tldrlegal.com/license/mozilla-public-license-2.0-(mpl-2))
