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

import EventEmitter from 'events';
import { ZitiSocket } from './ziti-socket';
import { ZitiInnerTLSSocket } from './ziti-inner-tls-socket';
import { isEqual, isUndefined } from 'lodash-es';



/**
 * Base HTTP "ZitiAgent" class. 
 *
 */
 class ZitiAgent extends EventEmitter {

    constructor(options) {
      super()
      this.options = Object.assign({}, options)
      this.proxy = options;
      this.secure = this.proxy.protocol && this.proxy.protocol === 'https:';
      this.defaultPort = 443;
    }
  
    /**
     * 
     */
    end() {
        // NOP
    }

    /**
     * Creates and returns a `ZitiSocket` instance to use for an HTTP request. If
     * the serviceScheme is 'https', then the socket will also embed a `ZitiInnerTLSSocket` 
     * instance to facilitate TLS traffic over/within the outer mTLS socket.
     *
     * @api public
     */
    async createConnection(opts, deferredFn) {

        opts.zitiContext.logger.trace(`ZitiAgent.createConnection() isNew=${opts.isNew} serviceScheme=${opts.serviceScheme}`);

        this.deferredFn = deferredFn;

        function innerTLSSocketOnData(data) {  
            let innerTLSSocket = this;
            let uint8View = new Uint8Array(data);
            innerTLSSocket._zitiContext.logger.trace(`ZitiAgent.innerTLSSocketOnData() emitting 'data' to outer socket`);
            innerTLSSocket.getOuterSocket().emit('data', uint8View);
        }
        function innerTLSSocketOnClose(data) {  
            let innerTLSSocket = this;
            innerTLSSocket._zitiContext.logger.trace(`ZitiAgent.innerTLSSocketOnClose() emitting 'close' to outer socket`);
            innerTLSSocket.getOuterSocket().emit('close', data);
            innerTLSSocket.getOuterSocket().innerTLSSocket = undefined;
        }

        /**
         * When this function is called, the mTLS connection to the service has succeeded
         */
        const onSocketConnect = async () => {
            this.proxy.zitiContext.logger.trace(`ZitiAgent.onSocketConnect() isNew[${opts.isNew}]`);

            if (opts.isNew) {   // Only do the nestedTLS/InnerTLSSocket create/connect work if we haven't already done it previously

                /**
                 * Also create the inner socket IF the service we are connecting to expects TLS traffic (i.e. web server listens on HTTPS).
                 */
                if (isEqual(this.proxy.serviceScheme, 'https') || isEqual(opts.serviceScheme, 'https:')) {

                    this.proxy.zitiContext.logger.trace(`ZitiAgent.onSocketConnect() creating ZitiInnerTLSSocket`);

                    let innerTLSSocket = new ZitiInnerTLSSocket( this.proxy );
                    innerTLSSocket.setWASMFD(this.proxy.zitiContext.addWASMFD(innerTLSSocket));
                    innerTLSSocket.setOuterSocket(this.socket);
                    this.socket.innerTLSSocket = innerTLSSocket;
                    await innerTLSSocket.create();
                    innerTLSSocket.on('data', innerTLSSocketOnData);
                    innerTLSSocket.on('close', innerTLSSocketOnClose);

                }

            }

            this.deferredFn(null, this.socket);
        };

        if (opts.isNew) {

            this.socket = new ZitiSocket( opts );
            this.socket.isNew = opts.isNew;
            opts.zitiContext.logger.trace(`ZitiAgent.createConnection() socket[${this.socket._id}] created`);
            this.socket.on('connect', onSocketConnect);
            await this.socket.connect(opts);

        } else {

            opts.zitiContext.logger.trace(`ZitiAgent.createConnection() socket[${this.socket._id}] reused`);
            this.socket.isNew = opts.isNew;
            this.socket.req = opts.req;
            await this.socket.connect(opts);
            // this.socket.on('connect', onSocketConnect);
            // this.socket.emit('connect', this.socket.zitiConnection);

        }
    }

}


export {
    ZitiAgent
};