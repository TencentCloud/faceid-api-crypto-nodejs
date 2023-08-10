const { createCipheriv, createDecipheriv, randomBytes } = require('crypto')
const Base = require('./base')
const NodeRSA = require('node-rsa')

class Instant extends Base {
  loadPK (pem, expire) {
    this.expires = expire
    this.pk = new NodeRSA(pem, 'pkcs1-public-pem', { encryptionScheme: 'pkcs1' })
    this.algName = 'AES-256-CBC'
  }

  genIV () {
    return randomBytes(16)
  }

  genSEK () {
    return randomBytes(32)
  }

  asymmetricEncrypt (data) {
    return this.pk.encrypt(data, 'base64')
  }

  symmetricDecrypt (sek, iv, data) {
    console.log(iv.length)
    const decipher = createDecipheriv('aes-256-cbc', sek, iv)
    let decryptedData = decipher.update(data, 'base64', 'utf-8')
    decryptedData += decipher.final('utf-8')
    return decryptedData
  }

  symmetricEncrypt (sek, iv, data) {
    const cipherChunks = []
    const cipher = createCipheriv('aes-256-cbc', sek, iv)
    cipher.setAutoPadding(true)
    cipherChunks.push(cipher.update(data, 'utf8', 'base64'))
    cipherChunks.push(cipher.final('base64'))
    return [cipherChunks.join(''), null]
  }
}
module.exports.instants = new Instant()
