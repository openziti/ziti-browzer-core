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
import { isUndefined, isNull, isEqual } from 'lodash-es';
import {Mutex, withTimeout} from 'async-mutex';
import { ZITI_CONSTANTS } from '../constants';

// import { Buffer } from 'buffer/';  // note: the trailing slash is important!

// class Queue {
//     constructor(logger) {
//       this.logger = logger;
//       this.elements = {};
//       this.head = 0;
//       this.tail = 0;
//       this.mutex = withTimeout(new Mutex(), 1 * 1000, new Error('timeout on Queue mutex'));
//     }
//     async enqueue(element) {
//         this.logger.trace(`Queue.enqueue() entered: `, element);
//         await this.mutex.runExclusive( () => {
//             this.elements[this.tail] = element;
//             this.tail++;
//         });
//         this.logger.trace(`Queue.enqueue() exiting: `, element);
//     }
//     async dequeue() {
//         this.logger.trace(`Queue.dequeue() entered`);
//         let item;
//         await this.mutex.runExclusive( () => {
//             item = this.elements[this.head];
//             delete this.elements[this.head];
//             this.head++;
//         });
//         this.logger.trace(`Queue.dequeue() exiting: `, item);
//         return item;
//     }
//     peek() {
//       return this.elements[this.head];
//     }
//     headNdx() {
//         return this.head;
//     }
//     peekNdx(ndx) {
//         return this.elements[ndx];
//     }
//     async acquireMutex() {
//         this.logger.trace(`Queue.acquireMutex() waiting for mutex`);
//         const release = await this.mutex.acquire();
//         this.logger.trace(`Queue.acquireMutex() now own mutex`);
//         return release;
//     }  
//     get length() {
//       return this.tail - this.head;
//     }
//     get isEmpty() {
//       return this.length === 0;
//     }
// }
  
class ZitiInnerTLSSocket extends EventEmitter {

    constructor(opts) {
        super();

        // this._connected_cb = null;
        this._connected = false;

        // this._read_cb = null;

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
        this._zitiContext = opts.zitiContext;

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
        // let self = this;
        // this._readableZitiStream = new ReadableStream({
        //     type: 'bytes',
        //     start(controller) {
        //         self._readableZitiStreamController = controller;
        //     }
        // });
        const { readable, writable } = new TransformStream();
        this._readable = readable;
        this._writable = writable;
        this._reader = this._readable.getReader();
        this._writer = this._writable.getWriter();
        this._readerBuffer = null;
        // this._q = new Queue(this._zitiContext.logger);

        this._fd_read_depth = 0;
        
        // this._reader = this._readableZitiStream.getReader({ 
        //     mode: "byob" 
        // });
        // this._readerBuffer = null;
 
        this._tlsReadLock = withTimeout(new Mutex(), 30 * 1000);
        this._tlsReadLockRelease = null;

        this._tlsProcessLock = withTimeout(new Mutex(), 30 * 1000, new Error('timeout on ZitiInnerTLSSocket._tlsProcessLock'));
        this._tlsProcessLockRelease = null;

        this._isConnectedMutex = withTimeout(new Mutex(), 30 * 1000, new Error('timeout on ZitiInnerTLSSocket._isConnectedMutex'));

        this.on(ZITI_CONSTANTS.ZITI_EVENT_XGRESS_RX_NESTED_TLS, this.processDataDecryption);

        this._tlsReadActive = false;

        this._closeEventPending = false;

        this.pendingWriteArray = new Uint8Array(0)

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

        this._privateKeyPEM = this._zitiContext.get_privateKeyPEM();

        this._certPEM = await this._zitiContext.getCertPEM();

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

        await this._zitiContext.acquireTLSHandshakeLock(this.getWASMFD());

        this._wasmInstance = await this._zitiContext.getWASMInstance();

        this._sslContext = await this._zitiContext.ssl_CTX_new( this._wasmInstance );

        this._BIO = this._zitiContext.bio_new_ssl_connect(this._wasmInstance, this._sslContext);

        this._SSL = this._zitiContext.bio_get_ssl(this._wasmInstance, this._BIO);
        this._zitiContext.logger.trace('ZitiInnerTLSSocket.create() SSL[%o] starting TLS handshake', this._SSL);


        // Tie the WASM-based SSL object back to this ZitiInnerTLSSocket so that later when
        // the low-level WASM code does fd-level i/o, our WASM-JS will intercept it, and
        // interface with this socket, so we can route traffic over our outer ZitiSocket, and
        // then on to the ER.
        this._zitiContext.ssl_set_fd( this._wasmInstance, this._SSL, this.getWASMFD() );

        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.create() wasmFD[${this.getWASMFD()}] starting TLS handshake`);

        this.handshake();
        
        let success = await this.awaitTLSHandshakeComplete( 30000 ).catch((error) => {

            // Let any listeners know the attempt to complete a nestedTLS handshake has timed out,
            // which is possibly a condition where the Service is misconfigured, and/or is not really
            // listening on HTTPS
            this._zitiContext.emit(ZITI_CONSTANTS.ZITI_EVENT_NESTED_TLS_HANDSHAKE_TIMEOUT, {
                serviceName: this.outerSocket.zitiConnection._data.serviceName,
                dst_hostname: this.outerSocket.zitiConnection._data.serviceConnectAppData.dst_hostname,
                dst_port: this.outerSocket.zitiConnection._data.serviceConnectAppData.dst_port,          
            });

            this._zitiContext.logger.error(`${error}`, this.getWASMFD());

            throw error;
        });
  
        if (success) {
            this._zitiContext.logger.trace(`ZitiInnerTLSSocket.create() wasmFD[${this.getWASMFD()}] TLS handshake completed pause start`);
            await this._zitiContext.delay(500); // allow the 'SSL negotiation finished successfully' work to complete
            this._zitiContext.logger.trace(`ZitiInnerTLSSocket.create() wasmFD[${this.getWASMFD()}] TLS handshake completed pause end`);
            this._zitiContext.releaseTLSHandshakeLock(this.getWASMFD());
        }
    }


    /**
     * Remain in lazy-sleepy loop until we have completed our TLS handshake.
     * 
     */
    async awaitTLSHandshakeComplete(threshold) {
        let self = this;
        let startTime = new Date();
        let ctr = 0;
        return new Promise((resolve, reject) => {
            (async function waitForTLSHandshakeComplete() {
                ctr++;
                let isConnected = await self.isConnected();
                if (!isConnected) {
                    if (ctr % 500 == 0) {
                        self._zitiContext.logger.trace(`ZitiInnerTLSSocket.awaitTLSHandshakeComplete() fd[${self.wasmFD}] TLS handshake still not complete`);
                    }
                    let now = new Date();
                    let elapsed = now - startTime; //in ms
                    if (elapsed > threshold) {
                        return reject(`Handshake Timeout threshold of [${threshold}] exceeded`);
                    }
                    setTimeout(waitForTLSHandshakeComplete, 10);  
                } else {
                    self._zitiContext.logger.trace(`ZitiInnerTLSSocket.awaitTLSHandshakeComplete() fd[${self.wasmFD}] TLS handshake complete`);
                    return resolve(true);
                }
            })();
        });
    }

    /**
     * 
     */
    async handshake() {
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.handshake(): fd[${this.wasmFD}] calling ssl_do_handshake()` );
        let result = await this._zitiContext.ssl_do_handshake( false, this.wasmFD, this._wasmInstance, this._SSL );
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.handshake(): fd[${this.wasmFD}] back from ssl_do_handshake(): result[${result}] (now awaiting cb)`);
    }

    /**
     * 
     */
    async isConnected() {

        // this._zitiContext.logger.trace(`ZitiInnerTLSSocket.isConnected() entered: fd[${this.wasmFD}] connected[${this._connected}]`);

        await this._isConnectedMutex.runExclusive( async () => {

            if (!this._connected) {

                // Ask the SSL if its handshake has completed yet
                let _connected = this._zitiContext.ssl_is_init_finished(this._wasmInstance, this._SSL);

                // this._zitiContext.logger.trace(`ZitiInnerTLSSocket.isConnected() ssl_is_init_finished() result: SSL[${this._SSL}] fd[${this.wasmFD}] connected[${_connected}]`);

                // If SSL indicates handshake has completed, let's delay a smidge, and allow the WASM mTLS ciphersuite-exchange to complete, 
                // before we turn loose any writes to the connection
                if (_connected) {
                    // this._zitiContext.logger.trace(`ZitiInnerTLSSocket.isConnected() pausing fd[${this.wasmFD}]`);
                    await this._zitiContext.delay(500);
                    // this._zitiContext.logger.trace(`ZitiInnerTLSSocket.isConnected() resuming fd[${this.wasmFD}]`);
                    this._connected = true;
                }
            }

        });

        return this._connected
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
    async tls_write(wireData) {
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.tls_write[${this.wasmFD}] unencrypted data is ready to be sent to the ER  ---> [%o]`, wireData);
        this._zitiContext.tls_write(this._wasmInstance, this._SSL, wireData);
    }

    /**
     * This function is called by the WASM-based TLS engine. The data we receive is now TLS encrypted at the innerTLS level, 
     * we now need to give it to the outer socket for mTLS-level encryption.
     * 
     * @param {*} wireData (already TLS-encrypted)
     */
    async fd_write(wireData) {
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write() fd[${this.wasmFD}]: encrypted data is ready`);
        const conn = await this.outerSocket.getZitiConnection();
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write() fd[${this.wasmFD}]: outerSocket[${this.outerSocket._id}] outerSocket.conn[${conn._id}]`);
        let isConnected = await this.isConnected();
        if (!isConnected) {
            this._zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write() fd[${this.wasmFD}]: (handshake data) is being sent to ch[${conn.channel.id}]  --->`);
            conn.channel.write(conn, wireData);
        } else {
            this._zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write() fd[${this.wasmFD}]: (encrypted data) is being sent to tlsConn[${conn.channel._tlsConn.wasmFD}]  --->`);

            //
            this._sendingEncryptedData = true;

            conn.channel.write(conn, wireData);
        }
    }

    _appendBuffer(buffer1, buffer2) {
        var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
        tmp.set(new Uint8Array(buffer1), 0);
        tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
        return tmp;
    };
      
    /**
     * 
     */
    async write(conn, buffer) {

        let MAX_IMMEDIATE_WRITE_LENGTH = 10; // data shorter than this goes out immediately
        let MAX_DELAY_WRITE_TIME       = 50; // number of ms to wait for more data before writing

        // Complete the TLS handshake if necessary
        let isConnected = await this.isConnected();
        if (!isConnected) {
            this.handshake();
            await this.awaitTLSHandshakeComplete();
        }
  
        if (buffer.length > 0) {

            if (buffer.length < MAX_IMMEDIATE_WRITE_LENGTH) {

                conn.channel.write(conn, buffer);

            }
            else {

                this.pendingWriteArray = this._appendBuffer(this.pendingWriteArray, buffer);

                this._zitiContext.logger.trace(`ZitiInnerTLSSocket.write() buffer.length[${buffer.length}] pendingWriteArray[${this.pendingWriteArray.length}]`);

                if (this.pendingWriteArray.length == buffer.length) {

                    setTimeout((self, conn) => {

                        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.write() AFTER TIMEOUT, now writing pendingWriteArray[${self.pendingWriteArray.length}]`);

                        conn.channel.write(conn, self.pendingWriteArray);

                        self.pendingWriteArray = new Uint8Array(0);
        
                    }, MAX_DELAY_WRITE_TIME, this, conn)
    
                }
            }
        }
    }

    /**
     * 
     * @param {*} arrayBuffer // ArrayBuffer
     */
     async process(arrayBuffer) {

        let isConnected = await this.isConnected();

        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.process() fd[${this.wasmFD}] isConnected[${isConnected}] encrypted data from outer socket arrived  <--- [${arrayBuffer.byteLength}]`);

        if (arrayBuffer.byteLength === 0) {

            // If the TLS handshake has completed, and we get a zero-length buffer...
            if (isConnected) {
                // ...then indicate we have a pending 'close' event.  The 'close' event will be emitted by the ClientRequest
                //      when it runs and sees the need to emit the event.  We need to defer/delay the emission of the 'close'
                //      event because it is possible that the data for this connection hasn't completed the decrypt flow yet, 
                //      and thus the HTTP Response pqrsing logic hasn't run yet, and if we issue a 'close' before then, the
                //      HTTP Response parsing logic will interpret the close as a 'socket hang up' error.

                this._closeEventPending = true;

            }

        } else {

            // Enqueue the encrypted data in the WASM heap
            await this._zitiContext.tls_enqueue(this._wasmInstance, this.wasmFD, arrayBuffer);
                
            // If the TLS handshake has completed
            if (isConnected) {

                this._zitiContext.logger.trace(`ZitiInnerTLSSocket.process() fd[${this.wasmFD}] this._tlsReadActive[${this._tlsReadActive}]`);

                // If there is no tls_read in flight
                if (!this._tlsReadActive) {

                    this._tlsReadActive = true;

                    // Then we need to do TLS-decrypt of the data, so fire an event to the handler that does the data decryption
                    this.emit(ZITI_CONSTANTS.ZITI_EVENT_XGRESS_RX_NESTED_TLS, {
                        self: this
                    });
                }
            }
        }
    }

    /**
     * 
     * @param {*} self // innerTLSSocket
     */
    async processDataDecryption(args) {

        let { self } = args;

        self._zitiContext.logger.trace(`ZitiInnerTLSSocket.processDataDecryption() fd[${self.wasmFD}] starting to decrypt enqueued data, calling tls_read`);

        let decryptedData = await self._zitiContext.tls_read(self._wasmInstance, self._SSL); // TLS-decrypt some data from the queue

        self._zitiContext.logger.trace(`ZitiInnerTLSSocket.processDataDecryption() fd[${self.wasmFD}] clear data from the outer socket is ready  <--- len[${decryptedData.byteLength}]`);
        self._zitiContext.logger.trace(`ZitiInnerTLSSocket.processDataDecryption() fd[${self.wasmFD}] emitting "data" from outer socket  <--- [${String.fromCharCode.apply(null, new Uint8Array(decryptedData))}]`);
        self.emit('data', decryptedData.buffer);

        // If there is still some pending encrypted data
        let item = self._zitiContext.peekTLSData( self._wasmInstance, self.wasmFD );
        self._zitiContext.logger.trace(`ZitiInnerTLSSocket.processDataDecryption() fd[${self.wasmFD}] peekTLSData returned [${item}]`);

        if (!isEqual(item, 0)) {

            self._zitiContext.logger.trace(`ZitiInnerTLSSocket.processDataDecryption() fd[${self.wasmFD}] pending encrypted data detected, so firing event so we run again`);

            // Then we need to do TLS-decrypt of that data, so fire an event so we run again
            self.emit(ZITI_CONSTANTS.ZITI_EVENT_XGRESS_RX_NESTED_TLS, {
                self: self
            });
            
        }
        else {
           
            this._tlsReadActive = false;
            
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
        await this._zitiContext.close(this.zitiConnection);
    }
    
    /**
     *
     */
    async end(data, encoding, callback) {
        this._writable = false;
        await this._zitiContext.close(this.zitiConnection);
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
    
    /**
     * 
     */
    async acquireTLSReadLock() {
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.acquireTLSReadLock() [${this.wasmFD}] trying to acquire _tlsReadLock`);
        this._tlsReadLockRelease = await this._tlsReadLock.acquire();
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.acquireTLSReadLock() [${this.wasmFD}] successfully acquired _tlsReadLock`);
    }
    releaseTLSReadLock() {
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.releaseTLSReadLock() [${this.wasmFD}] releasing _tlsReadLock`);
        this._tlsReadLockRelease();
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