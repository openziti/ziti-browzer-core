// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.

import { Transform } from './_stream_transform';
import EventEmitter from 'events';

class PassThrough extends Transform  {

  constructor (options) {
    super(options);
    this.ee = new EventEmitter()
  }

  _transform(chunk, encoding, cb) {
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

