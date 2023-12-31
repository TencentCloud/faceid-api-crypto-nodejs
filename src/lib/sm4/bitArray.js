/* eslint-disable prefer-const */
/* eslint-disable no-mixed-operators */
/* eslint-disable no-param-reassign */
/* eslint-disable no-underscore-dangle */

module.exports = {
  /**
   * Array slices in units of bits.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
   * slice until the end of the array.
   * @return {bitArray} The requested slice.
   */
  bitSlice (a, bstart, bend) {
    a = this._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31)).slice(1)
    return (bend === undefined) ? a : this.clamp(a, bend - bstart)
  },

  /**
   * Extract a number packed into a bit array.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} blength The length of the number to extract.
   * @return {Number} The requested slice.
   */
  extract (a, bstart, blength) {
    // FIXME: this Math.floor is not necessary at all, but for some reason
    // seems to suppress a bug in the Chromium JIT.
    let x; const sh = Math.floor((-bstart - blength) & 31)
    if ((bstart + blength - 1 ^ bstart) & -32) {
      // it crosses a boundary
      x = (a[bstart / 32 | 0] << (32 - sh)) ^ (a[bstart / 32 + 1 | 0] >>> sh)
    } else {
      // within a single word
      x = a[bstart / 32 | 0] >>> sh
    }
    return x & ((1 << blength) - 1)
  },

  /**
   * Concatenate two bit arrays.
   * @param {bitArray} a1 The first array.
   * @param {bitArray} a2 The second array.
   * @return {bitArray} The concatenation of a1 and a2.
   */
  concat (a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2)
    }

    const last = a1[a1.length - 1]; const shift = this.getPartial(last)
    if (shift === 32) {
      return a1.concat(a2)
    }
    return this._shiftRight(a2, shift, last | 0, a1.slice(0, a1.length - 1))
  },

  /**
   * Find the length of an array of bits.
   * @param {bitArray} a The array.
   * @return {Number} The length of a, in bits.
   */
  bitLength (a) {
    const l = a.length; let x
    if (l === 0) {
      return 0
    }
    x = a[l - 1]
    return (l - 1) * 32 + this.getPartial(x)
  },

  /**
   * Truncate an array.
   * @param {bitArray} a The array.
   * @param {Number} len The length to truncate to, in bits.
   * @return {bitArray} A new array, truncated to len bits.
   */
  clamp (a, len) {
    if (a.length * 32 < len) {
      return a
    }
    a = a.slice(0, Math.ceil(len / 32))
    const l = a.length
    len = len & 31
    if (l > 0 && len) {
      a[l - 1] = this.partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1)
    }
    return a
  },

  /**
   * Make a partial word for a bit array.
   * @param {Number} len The number of bits in the word.
   * @param {Number} x The bits.
   * @param {Number} [_end=0] Pass 1 if x has already been shifted to the high side.
   * @return {Number} The partial word.
   */
  partial (len, x, _end) {
    if (len === 32) {
      return x
    }
    return (_end ? x | 0 : x << (32 - len)) + len * 0x10000000000
  },

  /**
   * Get the number of bits used by a partial word.
   * @param {Number} x The partial word.
   * @return {Number} The number of bits used by the partial word.
   */
  getPartial (x) {
    return Math.round(x / 0x10000000000) || 32
  },

  /**
   * Compare two arrays for equality in a predictable amount of time.
   * @param {bitArray} a The first array.
   * @param {bitArray} b The second array.
   * @return {boolean} true if a == b; false otherwise.
   */
  equal (a, b) {
    if (this.bitLength(a) !== this.bitLength(b)) {
      return false
    }
    let x = 0; let i
    for (i = 0; i < a.length; i++) {
      x |= a[i] ^ b[i]
    }
    return (x === 0)
  },

  /** Shift an array right.
   * @param {bitArray} a The array to shift.
   * @param {Number} shift The number of bits to shift.
   * @param {Number} [carry=0] A byte to carry in
   * @param {bitArray} [out=[]] An array to prepend to the output.
   * @private
   */
  _shiftRight (a, shift, carry, out) {
    let i; let last2 = 0; let shift2
    if (out === undefined) {
      out = []
    }

    for (; shift >= 32; shift -= 32) {
      out.push(carry)
      carry = 0
    }
    if (shift === 0) {
      return out.concat(a)
    }

    for (i = 0; i < a.length; i++) {
      out.push(carry | a[i] >>> shift)
      carry = a[i] << (32 - shift)
    }
    last2 = a.length ? a[a.length - 1] : 0
    shift2 = this.getPartial(last2)
    out.push(this.partial(shift + shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(), 1))
    return out
  },

  /** xor a block of 4 words together.
   * @private
   */
  _xor4 (x, y) {
    return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]]
  },

  /** byteswap a word array inplace.
   * (does not handle partial words)
   * @param {bitArray} a word array
   * @return {bitArray} byteswapped array
   */
  byteswapM (a) {
    let i; let v; const m = 0xff00
    for (i = 0; i < a.length; ++i) {
      v = a[i]
      a[i] = (v >>> 24) | ((v >>> 8) & m) | ((v & m) << 8) | (v << 24)
    }
    return a
  },
  bytesFromBits (arr) {
    let out = []; let bl = this.bitLength(arr); let i; let tmp
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4]
      }
      out.push(tmp >>> 24)
      tmp <<= 8
    }
    return out
  },
  /** Convert from an array of bytes to a bitArray. */
  bytesToBits (bytes) {
    let out = []; let i; let tmp = 0
    for (i = 0; i < bytes.length; i++) {
      tmp = tmp << 8 | bytes[i]
      if ((i & 3) === 3) {
        out.push(tmp)
        tmp = 0
      }
    }
    if (i & 3) {
      out.push(this.partial(8 * (i & 3), tmp))
    }
    return out
  }
}
