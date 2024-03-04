// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.

import { Transform } from './_stream_transform';
import EventEmitter from 'events';
import pako from 'pako';
import { isEqual } from 'lodash-es';

class PassThrough extends Transform  {

  constructor (options) {
    super(options);
    this.ee = new EventEmitter();
    if (options.headers) {
      if (options.headers['content-encoding']) {
        if ( 
          isEqual(options.headers['content-encoding'].toLowerCase(), 'gzip')    ||
          isEqual(options.headers['content-encoding'].toLowerCase(), 'deflate')
        ) {
          this.isGzip = true;
          this.inflator = new pako.Inflate();
        }
      }
    }
  }

  _transform(chunk, encoding, cb) {
    if (this.isGzip) {
      this.inflator.push(chunk);
      chunk = this.inflator.result;
    }
    cb(null, chunk, this);
  };

  write(chunk, encoding, cb) {
    super._write(chunk, encoding, cb);
  }

  end() {
    this.ee.emit('end');
  }

}

export {
  PassThrough
};

