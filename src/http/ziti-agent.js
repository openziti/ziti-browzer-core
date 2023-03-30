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

import url from 'url';
import { ZitiSocket } from './ziti-socket';
import { ZitiInnerTLSSocket } from './ziti-inner-tls-socket';
import { isEqual, isUndefined } from 'lodash-es';



/**
 * Base HTTP "ZitiAgent" class. 
 *
 */

function ZitiAgent (opts) {

    if (!(this instanceof ZitiAgent)) return new ZitiAgent(opts);
    if ('string' == typeof opts) opts = url.parse(opts);
    // Agent.call(this);
    this.proxy = opts;
    this.secure = this.proxy.protocol && this.proxy.protocol === 'https:';
    // EventEmitter.call(this);

}

// inherits(ZitiAgent, EventEmitter);

/**
 * Default port to connect to.
 */

ZitiAgent.prototype.defaultPort = 443;

/**
 * Called when creating a new HTTP request with this ZitiAgent instance.
 *
 * @api public
 */

ZitiAgent.prototype.addRequest = function(req, host, port, localAddress) {

    let opts;
    if (typeof host == 'object') {
        // >= v0.11.x API
        opts = host;
    } else {
        // <= v0.10.x API
        opts = {
            host,
            port,
            localAddress,
        };
    }

    // hint to use "Connection: close"
    req.shouldKeepAlive = false;

    // create the `ZitiSocket` instance
    const info = {
        serviceName: opts.serviceName,
        serviceScheme: opts.serviceScheme,
        conn: opts.conn,
        host: opts.hostname || opts.host,
        port: Number(opts.port) || this.defaultPort,
        localAddress: opts.localAddress,
        isWebSocket: opts.isWebSocket,
        zitiContext: opts.zitiContext,
        req: req
    };

    this.createConnection(info, (err, socket) => {
        if (err) {
            req.emit('error', err);
        } else {
            req.onSocket(socket);
        }
    });
}



/**
 * Creates and returns a `ZitiSocket` instance to use for an HTTP request. If
 * the serviceScheme is 'https', then the socket will also embed a `ZitiInnerTLSSocket` 
 * instance to facilitate TLS traffic over/within the outer mTLS socket.
 *
 * @api public
 */

ZitiAgent.prototype.createConnection = async function(opts, deferredFn) {
    opts.zitiContext.logger.trace(`ZitiAgent.createConnection(): entered serviceScheme=${opts.serviceScheme}`);

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
        this.proxy.zitiContext.logger.trace(`ZitiAgent.onSocketConnect(): entered`);

        /**
         * Also create the inner socket IF the service we are connecting to expects TLS traffic (i.e. web server listens on HTTPS).
         */
        if (isEqual(this.proxy.serviceScheme, 'https')) {

            this.proxy.zitiContext.logger.trace(`ZitiAgent.onSocketConnect(): creating ZitiInnerTLSSocket`);

            let innerTLSSocket = new ZitiInnerTLSSocket( this.proxy );
            innerTLSSocket.setWASMFD(this.proxy.zitiContext.addWASMFD(innerTLSSocket));
            innerTLSSocket.setOuterSocket(this.socket);
            await innerTLSSocket.pullKeyPair();
            this.socket.innerTLSSocket = innerTLSSocket;
            await innerTLSSocket.create();
            innerTLSSocket.on('data', innerTLSSocketOnData);
            innerTLSSocket.on('close', innerTLSSocketOnClose);

        }

        this.deferredFn(null, this.socket);
    };

    this.socket = new ZitiSocket( opts );
    this.socket.connect(opts);
    this.socket.once('connect', onSocketConnect);
};


export {
    ZitiAgent
};