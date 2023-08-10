/* eslint-disable no-mixed-operators */
/* eslint-disable no-plusplus */
/* eslint-disable camelcase */
/* eslint-disable prefer-const */
/* eslint-disable no-param-reassign */
/* eslint-disable no-underscore-dangle */
const bitArray = require('./bitArray')
module.exports = {
  /**
   * The name of the mode.
   * @constant
   */
  name: 'gcm',

  /** Encrypt in GCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @return {bitArray} The encrypted data, an array of bytes.
   */
  encrypt (prf, plaintext, iv, adata, tlen) {
    let out; const data = plaintext.slice(0)
    tlen = tlen || 128
    adata = adata || []

    // encrypt and tag
    out = this._ctrMode(true, prf, data, adata, iv, tlen)

    return out
  },

  /** Decrypt in GCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @return {bitArray} The decrypted data.
   */
  decrypt (prf, ciphertext, iv, adata, tlen) {
    let out; let data = ciphertext.slice(0); let tag; const w = bitArray; const l = w.bitLength(data)
    tlen = tlen || 128
    adata = adata || []

    // Slice tag out of data
    if (tlen <= l) {
      tag = w.bitSlice(data, l - tlen)
      data = w.bitSlice(data, 0, l - tlen)
    } else {
      tag = data
      data = []
    }

    // decrypt and tag
    out = this._ctrMode(false, prf, data, adata, iv, tlen)

    if (!w.equal(out.tag, tag)) {
      throw new Error('gcm: tag doesn\'t match')
    }
    return out.data
  },

  /* Compute the galois multiplication of X and Y
   * @private
   */
  _galoisMultiply (x, y) {
    let i; let j; let xi; let Zi; let Vi; let lsb_Vi; const w = bitArray; const xor = w._xor4

    Zi = [0, 0, 0, 0]
    Vi = y.slice(0)

    // Block size is 128 bits, run 128 times to get Z_128
    for (i = 0; i < 128; i++) {
      xi = (x[Math.floor(i / 32)] & (1 << (31 - i % 32))) !== 0
      if (xi) {
        // Z_i+1 = Z_i ^ V_i
        Zi = xor(Zi, Vi)
      }

      // Store the value of LSB(V_i)
      lsb_Vi = (Vi[3] & 1) !== 0

      // V_i+1 = V_i >> 1
      for (j = 3; j > 0; j--) {
        Vi[j] = (Vi[j] >>> 1) | ((Vi[j - 1] & 1) << 31)
      }
      Vi[0] = Vi[0] >>> 1

      // If LSB(V_i) is 1, V_i+1 = (V_i >> 1) ^ R
      if (lsb_Vi) {
        Vi[0] = Vi[0] ^ (0xe1 << 24)
      }
    }
    return Zi
  },

  _ghash (H, Y0, data) {
    let Yi; let i; const l = data.length

    Yi = Y0.slice(0)
    for (i = 0; i < l; i += 4) {
      Yi[0] ^= 0xffffffff & data[i]
      Yi[1] ^= 0xffffffff & data[i + 1]
      Yi[2] ^= 0xffffffff & data[i + 2]
      Yi[3] ^= 0xffffffff & data[i + 3]
      Yi = this._galoisMultiply(Yi, H)
    }
    return Yi
  },

  /** GCM CTR mode.
   * Encrypt or decrypt data and tag with the prf in GCM-style CTR mode.
   * @param {Boolean} encrypt True if encrypt, false if decrypt.
   * @param {Object} prf The PRF.
   * @param {bitArray} data The data to be encrypted or decrypted.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata The associated data to be tagged.
   * @param {Number} tlen The length of the tag, in bits.
   */
  _ctrMode (encrypt, prf, data, adata, iv, tlen) {
    let H; let J0; let S0; let enc; let i; let ctr; let tag
    let last; let l; let bl; let abl; let ivbl; const w = bitArray

    // Calculate data lengths
    l = data.length
    bl = w.bitLength(data)
    abl = w.bitLength(adata)
    ivbl = w.bitLength(iv)

    // Calculate the parameters
    H = prf.doBlockCrypt(new Uint32Array([0, 0, 0, 0]))
    if (ivbl === 96) {
      J0 = iv.slice(0)
      J0 = w.concat(J0, [1])
    } else {
      J0 = this._ghash(H, [0, 0, 0, 0], iv)
      J0 = this._ghash(H, J0, [0, 0, Math.floor(ivbl / 0x100000000), ivbl & 0xffffffff])
    }
    S0 = this._ghash(H, [0, 0, 0, 0], adata)

    // Initialize ctr and tag
    ctr = J0.slice(0)
    tag = S0.slice(0)

    // If decrypting, calculate hash
    if (!encrypt) {
      tag = this._ghash(H, S0, data)
    }

    // Encrypt all the data
    for (i = 0; i < l; i += 4) {
      ctr[3]++
      enc = prf.doBlockCrypt(new Uint32Array(ctr))
      data[i] ^= enc[0]
      data[i + 1] ^= enc[1]
      data[i + 2] ^= enc[2]
      data[i + 3] ^= enc[3]
    }
    data = w.clamp(data, bl)

    // If encrypting, calculate hash
    if (encrypt) {
      tag = this._ghash(H, S0, data)
    }

    // Calculate last block from bit lengths, ugly because bitwise operations are 32-bit
    last = [
      Math.floor(abl / 0x100000000), abl & 0xffffffff,
      Math.floor(bl / 0x100000000), bl & 0xffffffff
    ]

    // Calculate the final tag block
    tag = this._ghash(H, tag, last)
    enc = prf.doBlockCrypt(new Uint32Array(J0))
    tag[0] ^= enc[0]
    tag[1] ^= enc[1]
    tag[2] ^= enc[2]
    tag[3] ^= enc[3]

    return { tag: w.bitSlice(tag, 0, tlen), data }
  }
}
