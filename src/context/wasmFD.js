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


class ZitiWASMFD {

    constructor(opts) {

        /**
         *  An id originating from ZitiContext.getNextWASMFDId()
         */
        this.id = opts.id;

        /**
         *  Either a ZitiWASMTLSConnection or a ZitiTLSSocket.
         *  Both of these objects include the necessary interface
         *  to facilitate the WASM calling into them when certain
         *  events occur.
         */
        this.socket = opts.socket;

    }

    getId() {
        return this.id;
    }

    getSocket() {
        return this.socket;
    }

}

export {
    ZitiWASMFD
};