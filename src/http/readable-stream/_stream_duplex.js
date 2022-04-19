//
// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.


import { Readable } from './_stream_readable';
import { Writable } from './_stream_writable';



class Duplex extends Readable  {
  constructor (options) {
    super(options);

    this._writable = new Writable(options);

    this.allowHalfOpen = true;
  
    if (options) {
      if (options.readable === false) this.readable = false;
      if (options.writable === false) this.writable = false;
  
      if (options.allowHalfOpen === false) {
        this.allowHalfOpen = false;
        this.once('end', this.onend);
      }
    }
  
  }

  _end() {
    this._writable.end();
  }

  get writableHighWaterMark() {
    return this._writable._writableState.highWaterMark;
  }
  
  get writableBuffer() {
    return this._writable._writableState && this._writable._writableState.getBuffer();
  }

  get writableLength() {
    return this._writable._writableState.length;
  }
  
  onend() {
    // If the writable side ended, then we're ok.
    if (this._writable._writableState.ended) return; // no more data can be written.
    // But allow more writes to happen in this tick.
  
    process.nextTick(this.onEndNT, this);
  }
  
  onEndNT(self) {
    self.end();
  }
  
  get destroyed() {
    if (this._readableState === undefined || this._writable._writableState === undefined) {
      return false;
    }
    return this._readableState.destroyed && this._writable._writableState.destroyed;
  }

  set destroyed(value) {
    if (this._readableState === undefined || this._writable._writableState === undefined) {
      return;
    }   
    this._readableState.destroyed = value;
    this._writable._writableState.destroyed = value;
  }
    
  write(chunk, encoding, cb) {
    return this._writable.write(chunk, encoding, cb);
  }
}


export {
  Duplex
};
