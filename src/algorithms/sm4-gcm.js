const { SM2: SM2lib } = require('gm-crypto')
const { randomBytes } = require('crypto')
const Base = require('./base')
const asn = require('asn1.js')
const SM4 = require('../lib/sm4')
const sm2PKObjID = asn.define('sm2PKObjID', function () {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('subAlgorithm').objid()
  )
})

const sm2PK = asn.define('sm2PK', function () {
  this.seq().obj(
    this.key('algorithm').use(sm2PKObjID),
    this.key('key').bitstr()
  )
})

const PUBLIC_OPENING_BOUNDARY = '-----BEGIN PUBLIC KEY-----'
const PUBLIC_CLOSING_BOUNDARY = '-----END PUBLIC KEY-----'

const trimSurroundingText = function (data, opening, closing) {
  let trimStartIndex = 0
  let trimEndIndex = data.length

  const openingBoundaryIndex = data.indexOf(opening)
  if (openingBoundaryIndex >= 0) {
    trimStartIndex = openingBoundaryIndex + opening.length
  }

  const closingBoundaryIndex = data.indexOf(closing, openingBoundaryIndex)
  if (closingBoundaryIndex >= 0) {
    trimEndIndex = closingBoundaryIndex
  }

  return data.substring(trimStartIndex, trimEndIndex)
}

const parseSM2PublicKey = (str) => {
  const pem = trimSurroundingText(str, PUBLIC_OPENING_BOUNDARY, PUBLIC_CLOSING_BOUNDARY)
    .replace(/\s+|\n\r|\n|\r$/gm, '')
  const buffer = Buffer.from(pem, 'base64')
  const sm2PublicKey = sm2PK.decode(buffer, 'der')
  return sm2PublicKey.key.data.toString('hex')
}

class Instant extends Base {
  loadPK (pem, expire) {
    this.expires = expire
    this.pk = parseSM2PublicKey(pem)
    this.algName = 'SM4-GCM'
  }

  genIV () {
    return randomBytes(12)
  }

  genSEK () {
    return randomBytes(16)
  }

  asymmetricEncrypt (data) {
    const cipherText = SM2lib.encrypt(data, this.pk, {
      mode: SM2lib.constants.C1C3C2,
      inputEncoding: 'utf-8',
      outputEncoding: 'base64',
      pc: true
    })
    return cipherText
  }

  symmetricDecrypt (sek, iv, data, tag) {
    const sm4 = new SM4({
      key: sek,
      mode: 'gcm',
      iv,
      cipherType: 'base64',
      adata: ''
    })
    return sm4.decrypt(data, tag)
  }

  symmetricEncrypt (sek, iv, data) {
    const sm4 = new SM4({
      key: sek,
      mode: 'gcm',
      iv,
      cipherType: 'base64',
      adata: ''
    })
    const { cipherText, tag } = sm4.encrypt(data)
    return [cipherText, tag]
  }
}
module.exports.instants = new Instant()
