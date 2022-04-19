
import { Duplex } from './_stream_duplex';

class Transform extends Duplex  {

  constructor (options) {
    super(options);

    this._transformState = {
      afterTransform: this.afterTransform,
      needTransform: false,
      transforming: false,
      writecb: null,
      writechunk: null,
      writeencoding: null
    }; // start out asking for a readable event once data is transformed.
  
    this._readableState.needReadable = true; // we have implemented the _read method, and done the other things
    // that Readable wants before the first _read call, so unset the
    // sync guard flag.
  
    this._readableState.sync = false;
  
    if (options) {
      if (typeof options.transform === 'function') this._transform = options.transform;
      if (typeof options.flush === 'function') this._flush = options.flush;
    } // When the writable side finishes, then flush out anything remaining.
  
  
    this.on('prefinish', this.prefinish);
  
  }

  afterTransform(er, data, self) {
    let _this = self;
    if (typeof this !== 'undefined') {
      _this = this;
    }
    var ts = _this._transformState;
    ts.transforming = false;
    var cb = ts.writecb;
  
    if (cb === null) {
      return _this.emit('error', new Error('Callback called multiple times'));
    }
  
    ts.writechunk = null;
    ts.writecb = null;
    if (data != null) // single equals check for both `null` and `undefined`
    _this.push(data);
    if (typeof cb !== 'undefined') {
      cb(er);
    }
    var rs = _this._readableState;
    rs.reading = false;
  
    if (rs.needReadable || rs.length < rs.highWaterMark) {
      _this._read(rs.highWaterMark);
    }
  }
  
  prefinish() {
    var _this = this;
  
    if (typeof this._flush === 'function' && !this._readableState.destroyed) {
      this._flush(function (er, data) {
        done(_this, er, data);
      });
    } else {
      done(this, null, null);
    }
  }
  
  push(chunk, encoding) {
    this._transformState.needTransform = false;
    return super.push(chunk, encoding);
  }; 
  
  // This is the part where you do stuff!
  // override this function in implementation classes.
  // 'chunk' is an input chunk.
  //
  // Call `push(newChunk)` to pass along transformed output
  // to the readable side.  You may call 'push' zero or more times.
  //
  // Call `cb(err)` when you are done with this chunk.  If you pass
  // an error, then that'll put the hurt on the whole operation.  If you
  // never call cb(), then you'll never get another chunk.
  
  _transform(chunk, encoding, cb) {
    cb(new ERR_METHOD_NOT_IMPLEMENTED('_transform()'));
  };

  _end() {
    super._end();
  }

  _write(chunk, encoding, cb) {
    var ts = this._transformState;
    ts.writecb = cb;
    ts.writechunk = chunk;
    ts.writeencoding = encoding;
  
    if (!ts.transforming) {
      var rs = this._readableState;
      if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
    }
  }; 
  
  // Doesn't matter what the args are here.
  // _transform does all the work.
  // That we got here means that the readable side wants more data.
  _read(n) {
    var ts = this._transformState;
  
    if (ts.writechunk !== null && !ts.transforming) {
      ts.transforming = true;
  
      this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
    } else {
      // mark that we need a transform, so that any data that comes in
      // will get processed, now that we've asked for it.
      ts.needTransform = true;
    }
  };
  
  _destroy(err, cb) {
    super._destroy(err, function (err2) {
      cb(err2);
    });
  };
  
  done(stream, er, data) {
    if (er) return stream.emit('error', er);
    if (data != null) // single equals check for both `null` and `undefined`
      stream.push(data); // TODO(BridgeAR): Write a test for these two error cases
    // if there's nothing in the write buffer, then that means
    // that nothing more will ever be provided
  
    if (stream._writableState.length) throw new Error('transform with length 0');
    if (stream._transformState.transforming) throw new Error('transform already transforming');
    return stream.push(null);
  }
  
}

export {
  Transform
};

