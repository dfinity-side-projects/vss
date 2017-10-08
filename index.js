
/**
 * creates a secert to share, an array of shares to share and a verifaction vector
 * @param {Object} bls - an instance of [bls-lib](https://github.com/wanderer/bls-lib)
 * @param {Number} numOfShares - the number of share to create
 * @param {Number} threshold - the number of share needed to recover the secret
 * @returns {Object} the return value contains `verifcationVector`, and array of `shares` and a random `secert`
 */
exports.createShare = function (bls, numOfShares, threshold) {
  // import secret
  // generate a sk and vvec
  const svec = []
  const vvec = []
  const shares = []
  for (let i = 0; i < threshold; i++) {
    const sk = bls.secretKey()
    bls.secretKeySetByCSPRNG(sk)
    svec.push(sk)

    const pk = bls.publicKey()
    bls.getPublicKey(pk, sk)
    vvec.push(pk)
  }

  // generate key shares
  for (let i = 1; i < numOfShares + 1; i++) {
    const sk = bls.secretKey()
    const id = bls.idImportFromInt(i)
    bls.secretKeyShare(sk, svec, id)
    shares.push({
      sk: bls.secretKeyExport(sk),
      id: i
    })
    bls.free(id)
    bls.free(sk)
  }

  const results = {
    verifcationVector: vvec.map(pk => bls.publicKeyExport(pk)),
    shares: shares,
    secret: bls.secretKeyExport(svec[0])
  }

  // clean up!
  bls.freeArray(vvec)
  bls.freeArray(svec)

  return results
}

/**
 * verifys a share again a verifcation vector
 * @param {Object} bls - an instance of [bls-lib](https://github.com/wanderer/bls-lib)
 * @param {Object} share - a share
 * @param {Array} vvec - the verifcation vector
 * @return {Boolean}
 */
exports.verifyShare = function (bls, share, vvec) {
  const pk1 = bls.publicKey()
  const sk = bls.secretKeyImport(share.sk)

  vvec = vvec.map(pk => bls.publicKeyImport(pk))

  const id = bls.idImportFromInt(share.id)
  bls.publicKeyShare(pk1, vvec, id)

  const pk2 = bls.publicKey()
  bls.getPublicKey(pk2, sk)

  const isEqual = bls.publicKeyIsEqual(pk1, pk2)

  bls.freeArray(vvec)
  bls.free(pk1)
  bls.free(pk2)
  bls.free(id)

  return Boolean(isEqual)
}

/**
 * verifys a share again a verifcation vector
 * @param {Array} shares - an array of unque shares containing threshold number of shares
 * @returns {Uint8Array} - the recovered secret
 */
exports.recoverSecret = function (bls, shares) {
  const sk = bls.secretKey()
  const sks = shares.map(s => bls.secretKeyImport(s.sk))
  const ids = shares.map(s => bls.idImportFromInt(s.id))
  bls.secretKeyRecover(sk, sks, ids)
  const result = bls.secretKeyExport(sk)

  bls.free(sk)
  bls.freeArray(sks)
  bls.freeArray(ids)
  return result
}
