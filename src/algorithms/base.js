/* eslint-disable no-unused-vars */
module.exports = class Base {
  constructor () {
    this.expires = 0
    this.sekCache = null
    this.pk = null
    this.algName = ''
  }

  /**
   *
   * @param {String} pem
   */
  loadPK (pem, keyExpireTime) { }

  /**
   *
   * @returns {Buffer}
   */
  genIV () { }
  genSEK () {}

  /**
   * @param {number} sekExpireTime
   * @returns {[Buffer, String]}
   */
  getSEK (sekExpireTime) {
    if (sekExpireTime > 0) {
      if (Date.now() - this.expires < 0 || this.cache === null) {
        const p = this.genSEK()
        const c = this.asymmetricEncrypt(p)
        this.cache = [p, c]
        this.expires = Date.now() + sekExpireTime
      }
      return this.cache
    }
    const p = this.genSEK()
    const c = this.asymmetricEncrypt(p)
    return [p, c]
  }

  asymmetricEncrypt (data) {}
  symmetricEncrypt (sek, iv, data) {}
  symmetricDecrypt (sek, iv, data, tag) {}
}
