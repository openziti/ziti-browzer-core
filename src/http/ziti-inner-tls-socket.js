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
import {Mutex, withTimeout} from 'async-mutex';
import { Buffer } from 'buffer/';  // note: the trailing slash is important!

class Queue {
    constructor(logger) {
      this.logger = logger;
      this.elements = {};
      this.head = 0;
      this.tail = 0;
      this.mutex = withTimeout(new Mutex(), 1 * 1000, new Error('timeout on Queue mutex'));
    }
    async enqueue(element) {
        this.logger.trace(`Queue.enqueue() entered: `, element);
        await this.mutex.runExclusive( () => {
            this.elements[this.tail] = element;
            this.tail++;
        });
        this.logger.trace(`Queue.enqueue() exiting: `, element);
    }
    async dequeue() {
        this.logger.trace(`Queue.dequeue() entered`);
        let item;
        await this.mutex.runExclusive( () => {
            item = this.elements[this.head];
            delete this.elements[this.head];
            this.head++;
        });
        this.logger.trace(`Queue.dequeue() exiting: `, item);
        return item;
    }
    peek() {
      return this.elements[this.head];
    }
    headNdx() {
        return this.head;
    }
    peekNdx(ndx) {
        return this.elements[ndx];
    }
    async acquireMutex() {
        this.logger.trace(`Queue.acquireMutex() waiting for mutex`);
        const release = await this.mutex.acquire();
        this.logger.trace(`Queue.acquireMutex() now own mutex`);
        return release;
    }  
    get length() {
      return this.tail - this.head;
    }
    get isEmpty() {
      return this.length === 0;
    }
}
  
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
        this._q = new Queue(this._zitiContext.logger);

        this._fd_read_depth = 0;
        
        // this._reader = this._readableZitiStream.getReader({ 
        //     mode: "byob" 
        // });
        // this._readerBuffer = null;
 
        this._tlsReadLock = withTimeout(new Mutex(), 30 * 1000);
        this._tlsReadLockRelease = null;

        this._tlsProcessLock = withTimeout(new Mutex(), 30 * 1000, new Error('timeout on ZitiInnerTLSSocket._tlsProcessLock'));
        this._tlsProcessLockRelease = null;
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

        this._privateKeyPEM = this._zitiContext.privateKeyPEM;

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

        this._sslContext = await this._zitiContext.ssl_CTX_new();

        this._BIO = this._zitiContext.bio_new_ssl_connect(this._sslContext);

        this._SSL = this._zitiContext.bio_get_ssl(this._BIO);


        // Tie the WASM-based SSL object back to this ZitiInnerTLSSocket so that later when
        // the low-level WASM code does fd-level i/o, our WASM-JS will intercept it, and
        // interface with this socket, so we can route traffic over our outer ZitiSocket, and
        // then on to the ER.
        this._zitiContext.ssl_set_fd( this._SSL, this.getWASMFD() );

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
                    self._zitiContext.logger.trace('ZitiInnerTLSSocket.awaitTLSHandshakeComplete() wasmFD[%d] TLS handshake still not complete', self.wasmFD);
                    setTimeout(waitForTLSHandshakeComplete, 10);  
                } else {
                    self._zitiContext.logger.trace('ZitiInnerTLSSocket.awaitTLSHandshakeComplete() wasmFD[%d] TLS handshake complete', self.wasmFD);
                    return resolve();
                }
            })();
        });
    }


    /**
     * 
     */
    handshake_cb(self, rc) {
        self._zitiContext.logger.trace('ZitiInnerTLSSocket.handshake_cb(): entered rc=%d ', rc );

        if (rc < 0) {
            throw new Error(`TLS handshake failed for fd[${self.wasmFD}]`);
        }

        // Let's delay a smidge, and allow the WASM mTLS ciphersuite-exchange to complete, 
        // before we turn loose any writes to the connection
        setTimeout((tlsConn, rc) => {
            self._zitiContext.logger.trace("ZitiInnerTLSSocket.handshake_cb(): after timeout");
            self._connected = true;
        }, 5, self, rc)
    }

    /**
     * 
     */
    handshake() {

        // Make sure WASM knows where to callback to once handshake is complete
        this._connected_cb = this.handshake_cb;

        this._zitiContext.logger.trace('ZitiInnerTLSSocket.handshake(): fd[%d] calling ssl_do_handshake()', this.wasmFD );
        let result = this._zitiContext.ssl_do_handshake( this._SSL );
        this._zitiContext.logger.trace('ZitiInnerTLSSocket.handshake(): fd[%d] back from ssl_do_handshake() for %o:  result=%d (now awaiting cb)', this.wasmFD,  this._id, result );
    }

    /**
     * 
     */
    captureResponseData(conn, data) {

        conn._zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() <- conn[%d], dataLen: [%o]", conn.id, data.byteLength);
        conn._zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() <- conn[%d], (string)data: [%s]", conn.id, Buffer.from(data, 'utf8'));

        let zitiSocket = conn.socket;
        let self = zitiSocket.innerTLSSocket;

        if (data.byteLength > 0) {

            // Push it into the stream that is read by fd_read
            // self._readableZitiStreamController.enqueue( new Uint8Array(data, 0) );
            self._writer.write( new Uint8Array(data, 0) );

            // If the TLS handshake has completed, we'll need to do TLS-decrypt of the data, 
            // and then propagate it to the Promise that is waiting for it.
            if (self._connected) {

                conn._zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() handshake previously completed [%d]", conn.id);

                // Make sure WASM knows where to callback to once data is ready
                self._read_cb = self.read_cb;

                self._zitiContext.tls_read(self._SSL); // TLS-decrypt some data from the queue

            } else {
                conn._zitiContext.logger.trace("ZitiInnerTLSSocket.captureResponseData() handshake not yet completed [%d]", conn.id);
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
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket.tls_write[${this.wasmFD}] unencrypted data is ready to be sent to the ER  ---> [%o]`, wireData);
        this._zitiContext.tls_write(this._SSL, wireData);
    }

    /**
     * This function is called by the WASM-based TLS engine. The data we receive is now TLS encrypted at the innerTLS level, 
     * we now need to give it to the outer socket for mTLS-level encryption.
     * 
     * @param {*} wireData (already TLS-encrypted)
     */
    async fd_write(wireData) {
        // this._zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write[${this.wasmFD}]: encrypted data is ready`);
        const conn = await this.outerSocket.getZitiConnection();
        if (!this._connected) {
            // this._zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write[${this.wasmFD}]: (handshake data) is being sent to ch[${conn.channel.id}]  --->`);
            conn.channel.write(conn, wireData);
        } else {
            // this._zitiContext.logger.trace(`ZitiInnerTLSSocket.fd_write[${this.wasmFD}]: (encrypted data) is being sent to tlsConn[${conn.channel._tlsConn.wasmFD}]  --->`);

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
    // async fd_read( len ) {
    //     this._fd_read_depth++;
    //     // await this.acquireTLSReadLock();
    //     this._zitiContext.logger.trace('ZitiInnerTLSSocket.fd_read: entered with len [%o] _fd_read_depth[%d]', len, this._fd_read_depth);
    //     let buffer = new ArrayBuffer( len );
    //     buffer = await this._readInto( buffer );
    //     this._fd_read_depth--;
    //     // this.releaseTLSReadLock();
    //     this._zitiContext.logger.trace('ZitiInnerTLSSocket.fd_read: returning buffer [%o]', buffer);
    //     return buffer;
    // }

    // _readFromReaderBuffer(targetBuffer, targetStart, targetLength) {
    //     this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readFromReaderBuffer[${this.wasmFD}]: targetBuffer[${targetBuffer}] targetStart[${targetStart}] targetLength[${targetLength}]`);
    //     this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readFromReaderBuffer[${this.wasmFD}]: _readerBuffer.byteLength[${this._readerBuffer.byteLength}] _readerBufferOffset+targetLength[${(this._readerBufferOffset + targetLength)}]`);
    //     if ((this._readerBufferOffset + targetLength) > this._readerBuffer.byteLength) {
    //         this._zitiContext.logger.error(`ZitiInnerTLSSocket._readFromReaderBuffer[${this.wasmFD}]: _readerBufferOffset+targetLength[${(this._readerBufferOffset + targetLength)}] exceeds _readerBuffer.byteLength[${this._readerBuffer.byteLength}]`);
    //     }

    //     let srcBuffer = new Buffer(this._readerBuffer);
    //     targetBuffer = new Buffer(targetBuffer);
    //     return srcBuffer.copy( targetBuffer, targetStart, this._readerBufferOffset, (this._readerBufferOffset + targetLength) );
    // }

    async _getQueueLength() {

        let release = await this._q.acquireMutex();

        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._getQueueLength[${this.wasmFD}]: DUMP -VVV------------------------------------`);

        let dumpctr = 0;
        for (const [key, value] of Object.entries(this._q.elements)) {
          this._zitiContext.logger.trace(`ZitiInnerTLSSocket._getQueueLength[${this.wasmFD}]: DUMP `, key, value);
          dumpctr += value.byteLength - value.offset;
          this._zitiContext.logger.trace(`ZitiInnerTLSSocket._getQueueLength[${this.wasmFD}]: DUMP `, (value.byteLength - value.offset), dumpctr);
        }
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._getQueueLength[${this.wasmFD}]: DUMP -^^^------------------------------------`, dumpctr);

        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._getQueueLength[${this.wasmFD}]: releasing mutex`);

        release();

        return dumpctr;
    }
  
    async _awaitTargetLengthPresent(targetLength) {

        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._awaitTargetLengthPresent[${this.wasmFD}]: entered for targetLength[${targetLength}]`);

        let totalLen = await this._getQueueLength();

        while (totalLen < targetLength) {
    
            this._zitiContext.logger.trace(`ZitiInnerTLSSocket._awaitTargetLengthPresent[${this.wasmFD}]: awaiting on _reader.read()`);
            const { value: view, done } = await this._reader.read();
            let chunk = {
                offset: 0,
                byteLength: view.buffer.byteLength,
                buffer: view.buffer
            }
            this._zitiContext.logger.trace(`ZitiInnerTLSSocket._awaitTargetLengthPresent[${this.wasmFD}]: returned from this._reader.read(), enqueueing new chunk of byteLength[${chunk.byteLength}]`);
            await this._q.enqueue( chunk );

            totalLen = await this._getQueueLength();
        }
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._awaitTargetLengthPresent[${this.wasmFD}]: returning totalLen[${totalLen}]`);

        return totalLen;
    }

    async _readInto(targetBuffer) {

        let remainingTargetLength = targetBuffer.byteLength;
        let targetBufferOffset = 0;
        targetBuffer = new Buffer(targetBuffer);

        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: entered, targetLength[${targetBuffer.byteLength}]`);

        // Do not proceed until the queue is populated with enough data to fulfill the read request
        let totalLen = await this._awaitTargetLengthPresent(remainingTargetLength);
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: totalLen in this._q is: `, totalLen);

        while (remainingTargetLength > 0) { // Until all requested bytes have been delivered

            let chunk = this._q.peek(); // Get top-most chunk, and determine unconsumed portion

            if (isUndefined(chunk)) {
                debugger
            }

            let remainingChunkLen = (chunk.byteLength - chunk.offset);
            this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: remainingTargetLength[${remainingTargetLength}] remainingChunkLen[${remainingChunkLen}]`);

            let srcBuffer = new Buffer(chunk.buffer);

            if (remainingChunkLen < remainingTargetLength) { // if chunk is too small to completely fulfill read request, then
                                                             // consume remaining contents of this chunk, then dispose of it
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: 1 copying at targetBufferOffset[${targetBufferOffset}] chunk.offset[${chunk.offset}]`);
                let bytesCopied = srcBuffer.copy( targetBuffer, targetBufferOffset, chunk.offset, (chunk.offset+remainingChunkLen));
                remainingTargetLength -= bytesCopied;
                targetBufferOffset += bytesCopied;
                chunk.offset += bytesCopied;
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: 1 bytesCopied[${bytesCopied}] remainingChunkLen[${(chunk.byteLength - chunk.offset)}] purging chunk`);
                await this._q.dequeue();
            }
            else if (remainingChunkLen == remainingTargetLength) { // if chunk will exactly fulfill read request, then
                                                                    // consume remaining contents of this chunk, then dispose of it
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: 2 copying at targetBufferOffset[${targetBufferOffset}] chunk.offset[${chunk.offset}]`);
                let bytesCopied = srcBuffer.copy( targetBuffer, targetBufferOffset, chunk.offset, (chunk.offset+remainingChunkLen));
                remainingTargetLength -= bytesCopied;
                chunk.offset += bytesCopied;
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: 2 bytesCopied[${bytesCopied}] remainingChunkLen[${(chunk.byteLength - chunk.offset)}] purging chunk`);
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: this._q before: `, this._q);
                await this._q.dequeue();
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: this._q after: `, this._q);
            } else {                                        // Chunk contains more than enough data to fulfill read request, so
                                                            // consume leading fragment of this chunk, update its offset, and leave it in the queue
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: 3 copying at targetBufferOffset[${targetBufferOffset}] chunk.offset[${chunk.offset}]`);
                let bytesCopied = srcBuffer.copy( targetBuffer, targetBufferOffset, chunk.offset, (chunk.offset+remainingTargetLength));
                remainingTargetLength -= bytesCopied;
                chunk.offset += bytesCopied;
                this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: 3 bytesCopied[${bytesCopied}] remainingChunkLen[${(chunk.byteLength - chunk.offset)}]`);
            }

        }
    
        this._zitiContext.logger.trace(`ZitiInnerTLSSocket._readInto[${this.wasmFD}]: exiting`);
    
        return targetBuffer.buffer;
    }


    /**
     * 
     */
    read_cb(self, buffer) {
        self._zitiContext.logger.trace('ZitiInnerTLSSocket.read_cb(): clear data from outer socket is ready  <--- [%o]', buffer);
        // If WASM passed an undefined buffer it means that there was a zero-length read from the socket
        if (isUndefined(buffer)) {
            console.log('ZitiInnerTLSSocket.read_cb(): emitting "close"');
            self.emit('close', buffer);
        } 
        // // Otherwise, emit the data to the listener
        else {
        //     // self._zitiContext.logger.trace('ZitiInnerTLSSocket.read_cb(): clear data from outer socket is ready  <--- [%o]', buffer);
            self._zitiContext.logger.trace('ZitiInnerTLSSocket.read_cb(): emitting "data" from outer socket  <--- [%s]', String.fromCharCode.apply(null, new Uint8Array(buffer)));
            self.emit('data', buffer);
        }
        // this._tlsProcessLockRelease();
    }    


    /**
     * 
     * @param {*} arrayBuffer // ArrayBuffer
     */
    async process(arrayBuffer) {
        this._zitiContext.logger.trace('ZitiInnerTLSSocket.process() fd[%d] encrypted data from outer socket arrived  <--- [%o]', this.wasmFD, arrayBuffer.byteLength);

        if (arrayBuffer.byteLength === 0) {

            // If the TLS handshake has completed, and we get a zero-length buffer...
            if (this._connected) {
                // ...then emit the 'close' event
                this._zitiContext.logger.trace("ZitiInnerTLSSocket.process() fd[%d] emitting 'close' event", this.wasmFD);
                this.emit('close', undefined);
            }

        } else {

            await this._zitiContext.tls_enqueue(this.wasmFD, arrayBuffer); // enqueue the encrypted data
            
            // If the TLS handshake has completed, we'll need to do TLS-decrypt of the data, 
            // and then propagate it to the Promise that is waiting for it.
            if (this._connected) {

                // Make sure WASM knows where to callback to once data is ready
                // this._read_cb = this.read_cb;

                let decryptedData = this._zitiContext.tls_read(this._SSL); // TLS-decrypt some data from the queue

                this._zitiContext.logger.trace('ZitiInnerTLSSocket.process[%d]: clear data from the outer socket is ready  <--- len[%d]', this.wasmFD, decryptedData.byteLength);
                this._zitiContext.logger.trace('ZitiInnerTLSSocket.read_cb(): emitting "data" from outer socket  <--- [%s]', String.fromCharCode.apply(null, new Uint8Array(decryptedData)));
                this.emit('data', decryptedData.buffer);
            }
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