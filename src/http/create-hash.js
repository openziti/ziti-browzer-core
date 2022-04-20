'use strict'

import MD5 from 'md5.js';
import RIPEMD160 from 'ripemd160';
import sha from 'sha.js';
import { CipherBase as Base } from './cipher-base';


class Hash extends Base {
    constructor(hash) {
        super('digest');
        this._hash = hash
    }

    _update = function (data) {
        this._hash.update(data)
    }
      
    _final = function () {
        return this._hash.digest()
    }
      
}

function createHash (alg) {
  alg = alg.toLowerCase()
  if (alg === 'md5') return new MD5()
  if (alg === 'rmd160' || alg === 'ripemd160') return new RIPEMD160()

  return new Hash(sha(alg))
}

export default createHash;