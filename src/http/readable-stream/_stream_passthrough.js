// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.

import { Transform } from './_stream_transform';
import EventEmitter from 'events';
import pako from 'pako';
import { isEqual, isUndefined } from 'lodash-es';

class PassThrough extends Transform  {

  constructor (options, zitiOptions) {
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
    this.zitiContext = zitiOptions.zitiContext;
  }

  _transform(chunk, encoding, cb) {
    if (this.isGzip) {
      this.inflator.push(chunk);
      chunk = this.inflator.result;

      /**
       * This logic was added on behalf of Solarwinds Orion, which embeds the host:port of the protected web server in some 
       * HTML/inline-JS (which is also gzip'ed). We must swap the hostname from the "protected web server" to the boot-strapper, 
       * or some downstream Orion logic will mismatch when doing some hostname comparisons, which leads it to NOT include 
       * an XSRF Token header on HTTP requests, which leads to 400's being returned fro teh web server, 
       * which leads to errors in Orion web UI.
       */
      if (!isUndefined(chunk)) {
        if (!isUndefined(this.zitiContext.targetServiceHostAndPort)) { // if we have a targetServiceHostAndPort
          let decodedChunk = new TextDecoder().decode(chunk);
          if (decodedChunk.indexOf(this.zitiContext.targetServiceHostAndPort) != -1) {
            decodedChunk = decodedChunk.replaceAll(this.zitiContext.targetServiceHostAndPort, this.zitiContext.bootstrapperHost);
            chunk = new TextEncoder().encode(decodedChunk);
          }
        }
      }
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

