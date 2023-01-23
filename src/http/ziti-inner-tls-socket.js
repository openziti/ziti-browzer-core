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

import EventEmitter from 'events';
import { isUndefined, isNull } from 'lodash-es';
import { Buffer } from 'buffer';

class ZitiInnerTLSSocket extends EventEmitter {

    constructor(opts) {
        super();

        this._connected_cb = null;
        this._connected = false;

        this._read_cb = null;

        this._datacb = opts.datacb;

    
        // /**
        //  * This stream is where we'll put any data returned from a Ziti connection (see ziti_dial.data.call_back)
        //  */
        // this.readableZitiStream = new ReadableStream({
        //     start(controller) {
        //         self.readableZitiStreamController = controller;
        //     }
        // });

        /**
         * The underlying Ziti Context
         * @private
         * @type {string}
         */
        this.zitiContext = opts.zitiContext;

        /**
         * The active HTTP request
         */
        this.req = opts.req;

        /**
         * The underlying Ziti Connection
         * @private
         * @type {string}
         */
        this.zitiConnection;


        /**
         * 
         */
        this._writable = false;

        /**
         * This stream is where we'll put any data arriving from an ER
         */
        let self = this;
        this._readableZitiStream = new ReadableStream({
            type: 'bytes',
            start(controller) {
                self._readableZitiStreamController = controller;
            }
        });
    
        this._reader = this._readableZitiStream.getReader({ 
            mode: "byob" 
        });
 
    }

    getWASMFD() {
        return this.wasmFD;
    }

    setWASMFD(wasmFD) {
        this.wasmFD = wasmFD;
    }

    setOuterSocket(outerSocket) {
        this.outerSocket = outerSocket;
    }
    getOuterSocket() {
        return this.outerSocket;
    }



    /**
     * Verify this TLS socket has the keypair/cert needed
     */
    async pullKeyPair() {

        this._privateKeyPEM = this.zitiContext.privateKeyPEM;

        this._certPEM = await this.zitiContext.getCertPEM();

        if (
            isUndefined(this._certPEM) ||
            isUndefined(this._privateKeyPEM) ||
            isNull(this._certPEM) ||
            isNull(this._privateKeyPEM)
        ) {
            throw new Error('keypair not present');
        }
    }  

    /**
     * 
     */
    async create() {

        this._sslContext = await this.zitiContext.ssl_CTX_new();

        this._BIO = this.zitiContext.bio_new_ssl_connect(this._sslContext);

        this._SSL = this.zitiContext.bio_get_ssl(this._BIO);


        // Tie the WASM-based SSL object back to this ZitiInnerTLSSocket so that later when
        // the low-level WASM code does fd-level i/o, our WAS-JS will intercept it, and
        // interface with this socket, so we can route traffic over our outer ZitiSocket, and
        // then on to the ER.
        this.zitiContext.ssl_set_fd( this._SSL, this.getWASMFD() );

    }


    /**
     * Remain in lazy-sleepy loop until we have completed our TLS handshake.
     * 
     */
    async awaitTLSHandshakeComplete() {
        let self = this;
        return new Promise((resolve) => {
            (function waitForTLSHandshakeComplete() {
                if (!self._connected) {
                    self.zitiContext.logger.trace('ZitiInnerTLSSocket.awaitTLSHandshakeComplete() wasmFD[%d] TLS handshake still not complete', self.wasmFD);
                    setTimeout(waitForTLSHandshakeComplete, 100);  
                } else {
                    self.zitiContext.logger.trace('ZitiInnerTLSSocket.awaitTLSHandshakeComplete() wasmFD[%d] TLS handshake is now complete', self.wasmFD);
                    return resolve();
                }
            })();
        });
    }


    /**
     * 
     */
    handshake_cb(self, rc) {
        self.zitiContext.logger.trace('ZitiInnerTLSSocket.handshake_cb(): entered rc=%d ', rc );

        // Let's delay a smidge, and allow the WASM mTLS ciphersuite-exchange to complete, 
        // before we turn loose any writes to the connection
        setTimeout((tlsConn, rc) => {
            self.zitiContext.logger.trace("ZitiInnerTLSSocket.handshake_cb(): after timeout");
            self._connected = true;
        }, 500, self, rc)
    }

    /**
     * 
     */
    handshake() {

        // Make sure WASM knows where to callback to once handshake is complete
        this._connected_cb = this.handshake_cb;

        let result = this.zitiContext.ssl_do_handshake( this._SSL );
        this.zitiContext.logger.trace('ZitiInnerTLSSocket.handshake(): back from ssl_do_handshake() for %o:  result=%d (now awaiting cb)', this._id, result );
    }

    /**
     * 
     */
    captureResponseData(conn, data) {

        conn.zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() <- conn[%d], dataLen: [%o]", conn.id, data.byteLength);
        conn.zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() <- conn[%d], (string)data: [%s]", conn.id, Buffer.from(data, 'utf8'));

        let zitiSocket = conn.socket;
        let self = zitiSocket.innerTLSSocket;

        if (data.byteLength > 0) {

            // Push it into the stream that is read by fd_read
            self._readableZitiStreamController.enqueue( new Uint8Array(data, 0) );
            
            // If the TLS handshake has completed, we'll need to do TLS-decrypt of the data, 
            // and then propagate it to the Promise that is waiting for it.
            if (self._connected) {

                conn.zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() handshake previously completed [%d]", conn.id);

                // Make sure WASM knows where to callback to once data is ready
                self._read_cb = self.read_cb;

                let buffer = self.zitiContext.tls_read(self._SSL); // TLS-decrypt some data from the stream

                conn.zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() <- tls_read (string)data: [%s]", buffer);

                // Note that execution returns here _before_ data is actually read from the stream
                if (!isNull(buffer)) {
                    self.zitiContext.logger.trace('ZitiInnerTLSSocket.captureResponseData() clear data from the server is ready  <--- ' );
                    self._datacb(self._ch, buffer); // propagate clear data to the waiting Promise
                }
            } else {
                conn.zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() handshake not yet completed [%d]", conn.id);
            }
        }
    }     

    /**
     * 
     */
    _read() { /* NOP */ }
    read()  { /* NOP */ }


    /**
     * 
     */
    destroy() { /* NOP */ }


    /**
     * 
     * @param {*} wireData (not TLS-encrypted yet)
     */
    tls_write(wireData) {
        this.zitiContext.logger.trace(`ZitiInnerTLSSocket.tls_write[${this.wasmFD}] unencrypted data is ready to be sent to the ER  ---> [%o]`, wireData);
        this.zitiContext.tls_write(this._SSL, wireData);
    }

    /**
     * This function is called by the WASM-based TLS engine. The data we receive is now TLS encrypted at the innerTLS level, 
     * we now need to give it to the outer socket for mTLS-level encryption.
     * 
     * @param {*} wireData (already TLS-encrypted)
     */
    async fd_write(wireData) {
        // this.zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write[${this.wasmFD}]: encrypted data is ready`);
        const conn = await this.outerSocket.getZitiConnection();
        if (!this._connected) {
            // this.zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write[${this.wasmFD}]: (handshake data) is being sent to ch[${conn.channel.id}]  --->`);
            conn.channel.write(conn, wireData);
        } else {
            // this.zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write[${this.wasmFD}]: (encrypted data) is being sent to tlsConn[${conn.channel._tlsConn.wasmFD}]  --->`);

            //
            this._sendingEncryptedData = true;

            conn.channel.write(conn, wireData);
        }
    }


    /**
     * 
     */
    async write(conn, buffer) {

        // Complete the TLS handshake if necessary
        if (!this._connected) {
            this.handshake();
            await this.awaitTLSHandshakeComplete();
        }
  
        if (buffer.length > 0) {
            conn.channel.write(conn, buffer);
        }
    }


    /**
     * 
     */
    async fd_read( len ) {
        // this.zitiContext.logger.trace('ZitiInnerTLSSocket.fd_read: entered with len [%o]', len);
        let buffer = new ArrayBuffer( len );
        buffer = await this._readInto( buffer );
        // this.zitiContext.logger.trace('ZitiInnerTLSSocket.fd_read: returning buffer [%o]', buffer);
        return buffer;
    }

    async _readInto(buffer) {
        let offset = 0;
    
        while (offset < buffer.byteLength) {
            // this.zitiContext.logger.trace('ZitiInnerTLSSocket._readInto: awaiting read');
            const { value: view, done } = await this._reader.read(new Uint8Array(buffer, offset, buffer.byteLength - offset));
            buffer = view.buffer;
            // this.zitiContext.logger.trace('ZitiInnerTLSSocket._readInto: added to buffer [%o]', buffer);
            if (done) {
                break;
            }
            offset += view.byteLength;
        }
    
        // this.zitiContext.logger.trace('ZitiInnerTLSSocket._readInto: returning buffer [%o]', buffer);
        return buffer;
    }


    /**
     * 
     */
    read_cb(self, buffer) {
        self.zitiContext.logger.trace('ZitiInnerTLSSocket.read_cb(): clear data from outer socket is ready  <--- [%o]', buffer);
        self.zitiContext.logger.trace('ZitiInnerTLSSocket.read_cb(): clear data from outer socket is ready  <--- [%s]', String.fromCharCode.apply(null, new Uint8Array(buffer)));
        self.emit('data', buffer);
        // self._datacb(self._ch, buffer); // propagate clear data to the waiting Promise
    }


    /**
     * 
     * @param {*} data 
     */
    process(data) {
        this.zitiContext.logger.trace('ZitiInnerTLSSocket.process() data from outer socket arrived  <--- [%o]', data);
        
        if (data.byteLength > 0) {

            // Push it into the stream that is read by fd_read
            this._readableZitiStreamController.enqueue( new Uint8Array(data, 0) );
            
            // If the TLS handshake has completed, we'll need to do TLS-decrypt of the data, 
            // and then propagate it to the Promise that is waiting for it.
            if (this._connected) {

                // Make sure WASM knows where to callback to once data is ready
                this._read_cb = this.read_cb;

                let buffer = this.zitiContext.tls_read(this._SSL); // TLS-decrypt some data from the stream

                // Note that execution returns here _before_ data is actually read from the stream
                if (!isNull(buffer)) {
                    this.zitiContext.logger.trace('ZitiInnerTLSSocket.process() clear data from the server is ready  <--- ' );
                    this._datacb(this._ch, buffer); // propagate clear data to the waiting Promise
                }
            }
        } else {
            this.emit('close', data);
        }
    }


    /**
     *
     */
    cork() {
        this._writable = false;
    }
    uncork() {
        this._writable = true;
    }

    /**
     *
     */
    pause() {
        this._writable = false;
    }
    resume() {
        this._writable = true;
    }

    /**
     *
     */
    async destroy() {
        this._writable = false;
        await this.zitiContext.close(this.zitiConnection);
    }
    
    /**
     *
     */
    async end(data, encoding, callback) {
        this._writable = false;
        await this.zitiContext.close(this.zitiConnection);
    }

    /**
     * Implements the writeable stream method `_final` used when .end() is called to write the final data to the stream.
     */
    _final(cb) {
        cb();
    }

    /**
     *
     */
    setTimeout() {
        /* NOP */
    }

    /**
     *
     */
    setNoDelay() {
        /* NOP */
    }

    /**
     *
     */
    unshift(head) {
        /* NOP */
    }
    
}

Object.defineProperty(ZitiInnerTLSSocket.prototype, 'writable', {
    get() {
      return (
        this._writable
      );
    }
});


export {
    ZitiInnerTLSSocket
};