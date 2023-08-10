const _ = require('lodash')
const debug = require('debug')('faceid-api-crypto-nodejs')
const sm4GCM = require('./algorithms/sm4-gcm')
const aes256CBC = require('./algorithms/aes-256-cbc')
// eslint-disable-next-line no-unused-vars
const Base = require('./algorithms/base')

const Algorithm = {
  AES256CBC: 'AES-256-CBC',
  SM4GCM: 'SM4-GCM'
}

let isInit = false
/**
 * @type {Base}
 */
let handler = null

const init = function (publicKey, algorithm, keyExpireTime = 0) {
  if (isInit) throw new Error('sdk has init')
  isInit = true
  if (!_.isNumber(keyExpireTime) || keyExpireTime < 0) {
    throw new Error('invalid param')
  }
  const pem = Buffer.from(publicKey, 'base64').toString()
  debug('pem', pem)
  if (algorithm === Algorithm.AES256CBC) {
    handler = aes256CBC.instants
  } else if (algorithm === Algorithm.SM4GCM) {
    handler = sm4GCM.instants
  } else {
    throw new Error('invalid param')
  }
  handler.loadPK(pem, keyExpireTime)
}

const modifyReqBody = function (reqBody, encryptList) {
  if (!isInit) throw new Error('not init')
  const req = _.cloneDeep(reqBody)
  const [plaintextKey, cipherTextBlob] = handler.getSEK()
  const iv = handler.genIV()
  const encryption = {
    EncryptList: encryptList,
    CiphertextBlob: cipherTextBlob,
    Iv: null,
    Algorithm: handler.algName,
    TagList: []
  }
  req.Encryption = encryption
  if (encryptList.length === 0) {
    return [req, plaintextKey]
  }
  encryption.Iv = iv.toString('base64')
  for (let i = 0; i < encryptList.length; i++) {
    const field = encryptList[i]
    const v = _.get(req, field)
    const [cipherValue, tag] = handler.symmetricEncrypt(plaintextKey, iv, v)
    console.log(field, v, cipherValue, tag)
    _.set(req, field, cipherValue)
    if (tag) encryption.TagList.push(tag)
  }
  return [req, plaintextKey]
}

const modifyRspBody = function (rspBody, plaintextKey) {
  if (!isInit) throw new Error('not init')
  const encryption = rspBody.Response.Encryption
  if (!encryption || !plaintextKey) {
    debug('ignore decrypt')
    return
  }
  // 参数校验
  const { EncryptList: encryptList, Iv: iv, Algorithm: algorithm, TagList: tagList } = encryption
  if (![Algorithm.AES256CBC, Algorithm.SM4GCM].includes(algorithm)) {
    debug('invalid algorithm')
    return
  }
  if (!(_.isArray(encryptList) && _.isArray(tagList))) {
    debug('invalid encryptList or tag')
    return
  }
  if (algorithm === Algorithm.SM4GCM && encryptList.length !== tagList.length) {
    debug('invalid list length')
    return
  }
  const ivBuffer = Buffer.from(iv, 'base64')
  // 遍历数组，解密数据
  for (let i = 0; i < encryptList.length; i++) {
    const field = encryptList[i]
    const tag = tagList[i]
    const cipherText = _.get(rspBody, field)
    const plainText = handler.symmetricDecrypt(plaintextKey, ivBuffer, cipherText, tag)
    _.set(rspBody, field, plainText)
  }
}

module.exports = {
  Algorithm,
  init,
  encrypt: modifyReqBody,
  decrypt: modifyRspBody
}
