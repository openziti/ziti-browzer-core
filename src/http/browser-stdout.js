/*
Copyright Netfoundry, Inc.

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

import WritableStream from 'stream';
import process from 'process';

class BrowserStdout extends WritableStream {

  constructor(opts) {
    super();
    opts = opts || {}
    WritableStream.call(this, opts)
    this.req = opts.req;  
  }

  _write(chunk, encoding, cb) {
    this.req.write( chunk );
    process.nextTick(cb);
  }

  write(chunk, encoding, cb) {
    this.req.write( chunk );
    if (cb) {
      process.nextTick(cb);
    }
  }

  end() { /* NOP */ }

}

export {
  BrowserStdout
};
