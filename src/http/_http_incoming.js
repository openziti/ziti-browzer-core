/*
Copyright NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


'use strict';

import { Readable } from './readable-stream/_stream_readable';

function readStart(socket) {
  if (socket && !socket._paused && socket.readable)
    socket.resume();
}

function readStop(socket) {
  if (socket)
    socket.pause();
}


// This function is used to help avoid the lowercasing of a field name if it
// matches a 'traditional cased' version of a field name. It then returns the
// lowercased name to both avoid calling toLowerCase() a second time and to
// indicate whether the field was a 'no duplicates' field. If a field is not a
// 'no duplicates' field, a `0` byte is prepended as a flag. The one exception
// to this is the Set-Cookie header which is indicated by a `1` byte flag, since
// it is an 'array' field and thus is treated differently in _addHeaderLines().
// TODO: perhaps http_parser could be returning both raw and lowercased versions
// of known header names to avoid us having to call toLowerCase() for those
// headers.
function matchKnownFields(field, lowercased) {
  switch (field.length) {
    case 3:
      if (field === 'Age' || field === 'age') return 'age';
      break;
    case 4:
      if (field === 'Host' || field === 'host') return 'host';
      if (field === 'From' || field === 'from') return 'from';
      if (field === 'ETag' || field === 'etag') return 'etag';
      if (field === 'Date' || field === 'date') return '\u0000date';
      if (field === 'Vary' || field === 'vary') return '\u0000vary';
      break;
    case 6:
      if (field === 'Server' || field === 'server') return 'server';
      if (field === 'Cookie' || field === 'cookie') return '\u0002cookie';
      if (field === 'Origin' || field === 'origin') return '\u0000origin';
      if (field === 'Expect' || field === 'expect') return '\u0000expect';
      if (field === 'Accept' || field === 'accept') return '\u0000accept';
      break;
    case 7:
      if (field === 'Referer' || field === 'referer') return 'referer';
      if (field === 'Expires' || field === 'expires') return 'expires';
      if (field === 'Upgrade' || field === 'upgrade') return '\u0000upgrade';
      break;
    case 8:
      if (field === 'Location' || field === 'location')
        return 'location';
      if (field === 'If-Match' || field === 'if-match')
        return '\u0000if-match';
      break;
    case 10:
      if (field === 'User-Agent' || field === 'user-agent')
        return 'user-agent';
      if (field === 'Set-Cookie' || field === 'set-cookie')
        return '\u0001';
      if (field === 'Connection' || field === 'connection')
        return '\u0000connection';
      break;
    case 11:
      if (field === 'Retry-After' || field === 'retry-after')
        return 'retry-after';
      break;
    case 12:
      if (field === 'Content-Type' || field === 'content-type')
        return 'content-type';
      if (field === 'Max-Forwards' || field === 'max-forwards')
        return 'max-forwards';
      break;
    case 13:
      if (field === 'Authorization' || field === 'authorization')
        return 'authorization';
      if (field === 'Last-Modified' || field === 'last-modified')
        return 'last-modified';
      if (field === 'Cache-Control' || field === 'cache-control')
        return '\u0000cache-control';
      if (field === 'If-None-Match' || field === 'if-none-match')
        return '\u0000if-none-match';
      break;
    case 14:
      if (field === 'Content-Length' || field === 'content-length')
        return 'content-length';
      break;
    case 15:
      if (field === 'Accept-Encoding' || field === 'accept-encoding')
        return '\u0000accept-encoding';
      if (field === 'Accept-Language' || field === 'accept-language')
        return '\u0000accept-language';
      if (field === 'X-Forwarded-For' || field === 'x-forwarded-for')
        return '\u0000x-forwarded-for';
      break;
    case 16:
      if (field === 'Content-Encoding' || field === 'content-encoding')
        return '\u0000content-encoding';
      if (field === 'X-Forwarded-Host' || field === 'x-forwarded-host')
        return '\u0000x-forwarded-host';
      break;
    case 17:
      if (field === 'If-Modified-Since' || field === 'if-modified-since')
        return 'if-modified-since';
      if (field === 'Transfer-Encoding' || field === 'transfer-encoding')
        return '\u0000transfer-encoding';
      if (field === 'X-Forwarded-Proto' || field === 'x-forwarded-proto')
        return '\u0000x-forwarded-proto';
      break;
    case 19:
      if (field === 'Proxy-Authorization' || field === 'proxy-authorization')
        return 'proxy-authorization';
      if (field === 'If-Unmodified-Since' || field === 'if-unmodified-since')
        return 'if-unmodified-since';
      break;
  }
  if (lowercased) {
    return '\u0000' + field;
  }
  return matchKnownFields(field.toLowerCase(), true);
}



class IncomingMessage extends Readable  {
  constructor (socket) {
    super();

    let streamOptions;

    if (socket) {
      streamOptions = {
        highWaterMark: socket.readableHighWaterMark
      };
    }
  
    // Readable.call(this, { autoDestroy: false, ...streamOptions });
  
    this._readableState.readingMore = true;
  
    this.socket = socket;
  
    this.httpVersionMajor = null;
    this.httpVersionMinor = null;
    this.httpVersion = null;
    this.complete = false;
    this.headers = {};
    this.rawHeaders = [];
    this.trailers = {};
    this.rawTrailers = [];
  
    this.aborted = false;
  
    this.upgrade = null;
  
    // request (server) only
    this.url = '';
    this.method = null;
  
    // response (client) only
    this.statusCode = null;
    this.statusMessage = null;
    this.client = socket;
  
    this._consuming = false;
    // Flag for when we decide that this message cannot possibly be
    // read by the user, so there's no point continuing to handle it.
    this._dumped = false;  
  }

  get connection() {
    return this.socket;
  }
  set connection(val) {
    this.socket = val;
  }
  
  setTimeout(msecs, callback) {
    if (callback)
      this.on('timeout', callback);
    this.socket.setTimeout(msecs);
    return this;
  };
  
  _read(n) {
    if (!this._consuming) {
      this._readableState.readingMore = false;
      this._consuming = true;
    }
  
    // We actually do almost nothing here, because the parserOnBody
    // function fills up our internal buffer directly.  However, we
    // do need to unpause the underlying socket so that it flows.
    if (this.socket.readable)
      readStart(this.socket);
  };
    
  // It's possible that the socket will be destroyed, and removed from
  // any messages, before ever calling this.  In that case, just skip
  // it, since something else is destroying this connection anyway.
  // destroy(error) {
  //   // TODO(ronag): Implement in terms of _destroy
  //   this.destroyed = true;
  //   if (this.socket)
  //     this.socket.destroy(error);
  //   return this;
  // };

  
  _addHeaderLines(headers, n) {
    if (headers && headers.length) {
      let dest;
      if (this.complete) {
        this.rawTrailers = headers;
        dest = this.trailers;
      } else {
        this.rawHeaders = headers;
        dest = this.headers;
      }
  
      for (let i = 0; i < n; i += 2) {
        this._addHeaderLine(headers[i], headers[i + 1], dest);
      }
    }
  }
  

  // Add the given (field, value) pair to the message
  //
  // Per RFC2616, section 4.2 it is acceptable to join multiple instances of the
  // same header with a ', ' if the header in question supports specification of
  // multiple values this way. The one exception to this is the Cookie header,
  // which has multiple values joined with a '; ' instead. If a header's values
  // cannot be joined in either of these ways, we declare the first instance the
  // winner and drop the second. Extended header fields (those beginning with
  // 'x-') are always joined.
  _addHeaderLine(field, value, dest) {
    field = matchKnownFields(field);
    const flag = field.charCodeAt(0);
    if (flag === 0 || flag === 2) {
      field = field.slice(1);
      // Make a delimited list
      if (typeof dest[field] === 'string') {
        dest[field] += (flag === 0 ? ', ' : '; ') + value;
      } else {
        dest[field] = value;
      }
    } else if (flag === 1) {
      // Array header -- only Set-Cookie at the moment
      if (dest['set-cookie'] !== undefined) {
        dest['set-cookie'].push(value);
      } else {
        dest['set-cookie'] = [value];
      }
    } else if (dest[field] === undefined) {
      // Drop duplicates
      dest[field] = value;
    }
  }


  // Call this instead of resume() if we want to just
  // dump all the data to /dev/null
  _dump() {
    if (!this._dumped) {
      this._dumped = true;
      // If there is buffered data, it may trigger 'data' events.
      // Remove 'data' event listeners explicitly.
      this.removeAllListeners('data');
      this.resume();
    }
  };

}



export {
  IncomingMessage,
  readStart,
  readStop
};
