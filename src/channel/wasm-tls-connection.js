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

/**
 * Module dependencies.
 */

import { Buffer } from 'buffer/';  // note: the trailing slash is important!
import { flatOptions } from '../utils/flat-options'
import { defaultOptions } from './wasm-tls-connection-options'
import { isUndefined, isNull } from 'lodash-es';
import { v4 as uuidv4 } from 'uuid';
// import { PassThrough } from '../http/readable-stream/_stream_passthrough';
// import { Duplex } from '../http/readable-stream/_stream_duplex';
// import { Transform } from '../http/readable-stream/_stream_transform';



/**
 *    ZitiWASMTLSConnection
 */
 class ZitiWASMTLSConnection {

  /**
   * 
   */
  constructor(options) {

    this._options = flatOptions(options, defaultOptions);

    this._zitiContext = this._options.zitiContext;

    this._ws = this._options.ws;
    this._socket = this._options.socket;

    this._ch = this._options.ch;
    this._id = this._ch.id;
    this._datacb = this._options.datacb;

    this._connected_cb = null;
    this._connected = false;

    this._read_cb = null;

    this._uuid = uuidv4();

    this._zitiContext.logger.trace('ZitiWASMTLSConnection.ctor: %o, _ws: %o', this._uuid, this._ws);

    /**
     * This stream is where we'll put any data arriving from an ER
     */
    const { readable, writable } = new TransformStream();
    this._readable = readable;
    this._writable = writable;
    this._reader = this._readable.getReader();
    this._writer = this._writable.getWriter();
    this._readerBuffer = null;


    // this._readableZitiStream = new ReadableStream({
    //   type: 'bytes',
    //   start(controller) {
    //     self._readableZitiStreamController = controller;
    //   }
    // });

    // this._reader = this._readableZitiStream.getReader({ 
      // mode: "byob" 
    // });

  }
 
  getWASMFD() {
    return this.wasmFD;
  }

  setWASMFD(wasmFD) {
    this.wasmFD = wasmFD;
  }

  /**
   * Verify this WASM TLS Connection object has the keypair/cert needed
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
 

  getUUID() {
    return this._uuid;
  }


  /**
   * 
   */
  async create() {

    this._sslContext = await this._zitiContext.ssl_CTX_new();

    this._BIO = this._zitiContext.bio_new_ssl_connect(this._sslContext);

    this._SSL = this._zitiContext.bio_get_ssl(this._BIO);


    // Tie the WASM-based SSL object back to this ZitiWASMTLSConnection so that later when
    // the low-level WASM code does fd-level i/o, our WAS-JS will intercept it, and
    // interface with this connection, so we can route traffic over the WebSocket to the ER
    this._zitiContext.ssl_set_fd( this._SSL, this._ch.id );

  }

  // encrypted data is ready to be sent to the server  --->
  tlsDataReady(connection) {
    let chunk = new Buffer(connection.tlsData.getBytes(), "binary");
    if (chunk.length > 0) {
      self._zitiContext.logger.trace('ZitiWASMTLSConnection.tlsDataReady: encrypted data is ready to be sent to the server  ---> ', chunk);
      self._ws.send(chunk);
    }
  }

  // clear data from the server is ready               <---
  dataReady(connection) {
    let chunk = new Buffer(connection.data.getBytes(), "binary");
    let ab = chunk.buffer.slice(0, chunk.byteLength);
    self._zitiContext.logger.trace('ZitiWASMTLSConnection.dataReady: clear data from the server is ready  <--- ' );
    self._datacb(self._ch, ab);
  }
  

  /**
   * 
   */
  getCertificate() {
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.getCertificate(): for: %o: ', this._id, this._certPEM );
    return self._certPEM;
  }

  /**
   *
   */      
  getPrivateKey() {
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.getPrivateKey(): for: %o: ', this._id, this._privateKeyPEM );
    return self._privateKeyPEM;
  }

  /**
   * 
   */
  handshake_cb(self, rc) {
    self._zitiContext.logger.trace('ZitiWASMTLSConnection.handshake_cb(): entered rc=%d ', rc );

    // Let's delay a smidge, and allow the WASM mTLS ciphersuite-exchange to complete, 
    // before we turn loose any writes to the connection
    setTimeout((tlsConn, rc) => {
      self._zitiContext.logger.trace("ZitiWASMTLSConnection.handshake_cb(): after timeout");
      self._connected = true;
    }, 500, self, rc)
  }

  /**
   * 
   */
  handshake() {

    // Make sure WASM knows where to callback to once handshake is complete
    this._connected_cb = this.handshake_cb;

    let result = this._zitiContext.ssl_do_handshake( this._SSL );
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.handshake(): back from ssl_do_handshake() for %o:  result=%d (now awaiting cb)', this._id, result );
  }

  ssl_get_verify_result() {
    let result = this._zitiContext.ssl_get_verify_result( this._SSL );
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.ssl_get_verify_result(): for: %o:  result: ', this._id, result );
    return result;
  }

  /**
   * 
   */
  get connected() {
    return this._connected;
  }
  set connected(state) {
    this._connected = state;
  }


  /**
   * 
   */
  write(buffer) {
    this._ws.send(buffer);
  }

  /**
   * 
   */
  read(buffer) {
    self._ws.send(buffer);
  }

  /**
   * 
   */
  read_cb(self, buffer) {
    self._zitiContext.logger.trace('ZitiWASMTLSConnection.read_cb(): clear data from the ER is ready  <--- len[%d]', buffer.byteLength);
    self._datacb(self._ch, buffer); // propagate clear data to the waiting Promise
  }

  /**
   * 
   * @param {*} data 
   */
  process(data) {
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.process() data from the ER arrived  <--- [%o]', data);
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.process() innerTLSSocket [%o]', this._socket.innerTLSSocket);
    
    // Push it into the stream that is read by fd_read
    // this._readableZitiStreamController.enqueue( new Uint8Array(data, 0) );
    this._writer.write( new Uint8Array(data, 0) );
    
    // If the TLS handshake has completed, we'll need to do TLS-decrypt of the data, 
    // and then propagate it to the Promise that is waiting for it.
    if (this._connected) {

      // Make sure WASM knows where to callback to once data is ready
      this._read_cb = this.read_cb;

      let buffer = this._zitiContext.tls_read(this._SSL); // TLS-decrypt some data from the stream

      // Note that execution returns here _before_ data is actually read from the stream
      if (!isNull(buffer)) {
        this._zitiContext.logger.trace('ZitiWASMTLSConnection.process() clear data from the server is ready  <--- ' );
        this._datacb(this._ch, buffer); // propagate clear data to the waiting Promise
      }
    }
  }
  
  /**
   * 
   * @param {*} wireData (not TLS-encrypted yet)
   */
   prepare(wireData) {
    // this._zitiContext.logger.trace('ZitiWASMTLSConnection.prepare() unencrypted data is ready to be sent to the ER  ---> [%o]', wireData);
    let tlsBinaryString = Buffer.from(wireData).toString('binary')
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.prepare() unencrypted data is ready to be sent to the ER  ---> len[%d]', tlsBinaryString.byteLength);
    this._tlsClient.prepare(tlsBinaryString);
  }

  /**
   * 
   * @param {*} wireData (not TLS-encrypted yet)
   */
  tls_write(wireData) {
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.tls_write unencrypted data is ready to be sent to the ER  ---> [%o]', wireData);
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.tls_write _socket.innerTLSSocket [%o]', this._socket.innerTLSSocket);
        
    // If we have an innerTLSsocket, and it has completed its TLS handshake
    if (!isUndefined(this._socket.innerTLSSocket) && this._socket.innerTLSSocket._connected ) {
      // If the innerTLSsocket has already encrypted the wireData...
      if (this._socket.innerTLSSocket._sendingEncryptedData) {
        // ...then pass it to the Channel
        this._zitiContext.logger.trace('ZitiWASMTLSConnection.tls_write sending encrypted wireData from innerTLSSocket to _zitiContext.tls_write');
        this._socket.innerTLSSocket._sendingEncryptedData = false; // reset now that we're sending to outer socket
        this._zitiContext.tls_write(this._SSL, wireData);
      } else {
        // ...otherwise pass it to the innerTLSsocket so it can do the necessary TLS encryption according to the handshake that was completed with
        // the connected service (i.e. web server listening on TLS)
        this._zitiContext.logger.trace('ZitiWASMTLSConnection.tls_write sending un-encrypted wireData to innerTLSSocket.tls_write');
        this._socket.innerTLSSocket.tls_write(wireData);
      }
    } else {
      this._zitiContext.logger.trace('ZitiWASMTLSConnection.tls_write no connected innerTLSSocket so sending un-encrypted wireData to _zitiContext.tls_write');
      this._zitiContext.tls_write(this._SSL, wireData);
    }
  }

  /**
   * 
   * @param {*} wireData (TLS-encrypted at the innerTLS level, but not TLS-encrypted at mTLS level yet)
   */
  tls_write_outer(wireData) {
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.tls_write_outer[%o] unencrypted data is ready to be sent to the ER  ---> [%o]', this._uuid, wireData);
    this._zitiContext.tls_write(this._SSL, wireData.buffer);
  }
  
  /**
   * 
   * @param {*} wireData (already TLS-encrypted)
   */
  fd_write(wireData) {
    // this._zitiContext.logger.trace('ZitiWASMTLSConnection.fd_write[%o] encrypted data is being sent to the ER  ---> [%o]', this._uuid, wireData); 
    this._ws.send(wireData);
  }

  /**
   * 
   */
  async fd_read( len ) {
    this._zitiContext.logger.trace(`ZitiWASMTLSConnection.fd_read[${this._id}]: entered with len[${len}]`);
    let buffer = new ArrayBuffer( len );
    buffer = await this._readInto( buffer );
    this._zitiContext.logger.trace(`ZitiWASMTLSConnection.fd_read[${this._id}]: returning buffer.byteLength[${buffer.byteLength}]`);
    return buffer;
  }

  _readFromReaderBuffer(targetBuffer, targetStart, targetLength) {
    let srcBuffer = new Buffer(this._readerBuffer);
    targetBuffer = new Buffer(targetBuffer);
    return srcBuffer.copy( targetBuffer, targetStart, this._readerBufferOffset, (this._readerBufferOffset + targetLength) );
  }

  async _readInto(targetBuffer) {
    let targetLength = targetBuffer.byteLength;
    let targetBufferOffset = 0;

    this._zitiContext.logger.trace(`ZitiWASMTLSConnection._readInto[${this._id}]: 1 targetLength[${targetLength}]`);

    while (targetBufferOffset < targetLength) {

      this._zitiContext.logger.trace(`ZitiWASMTLSConnection._readInto[${this._id}]: 2 targetBufferOffset[${targetBufferOffset}] targetLength[${targetLength}]`);

      if (this._readerBuffer !== null) {

        let bytesCopied = this._readFromReaderBuffer(targetBuffer, targetBufferOffset, targetLength);
        this._readerBufferOffset += bytesCopied;
        this._zitiContext.logger.trace(`ZitiWASMTLSConnection._readInto[${this._id}]: 3 _readerBuffer len [${this._readerBuffer.byteLength}] _readerBufferOffset [${this._readerBufferOffset}]`);
        targetBufferOffset += bytesCopied;
        if (this._readerBufferOffset === this._readerBuffer.byteLength) { // if we consumed everything
          this._readerBuffer = null;
          this._zitiContext.logger.trace(`ZitiWASMTLSConnection._readInto[${this._id}]: 4 _readerBuffer reset to NULL`);
        }

      } else {

        this._zitiContext.logger.trace(`ZitiWASMTLSConnection._readInto[${this._id}]: 5 now doing await of this._reader.read()`);
        const { value: view, done } = await this._reader.read();
        this._readerBuffer = view.buffer;
        this._readerBufferOffset = 0;
        this._zitiContext.logger.trace(`ZitiWASMTLSConnection._readInto[${this._id}]: 6 returned from await of this._reader.read(), this._readerBuffer.byteLength is [${this._readerBuffer.byteLength}]`);
      }

    }

    this._zitiContext.logger.trace(`ZitiWASMTLSConnection._readInto[${this._id}]: 7 exiting`);

    return targetBuffer;


  
    // while (offset < buffer.byteLength) {
    //   this._zitiContext.logger.trace('ZitiWASMTLSConnection._readInto: awaiting read');
    //   // const { value: view, done } = await this._reader.read(new Uint8Array(buffer, offset, buffer.byteLength - offset));
    //   // const { value: view, done } = await this._reader.read(new Uint8Array(buffer, offset, buffer.byteLength - offset));
    //   const { value: view, done } = await this._reader.read();
    //   if (this._readerBuffer === null) {
    //     this._readerBuffer = view.buffer;
    //     this._readerBufferOffset = 0;
    //   }
    //   buffer = view.buffer;
    //   this._zitiContext.logger.trace('ZitiWASMTLSConnection._readInto: added to buffer [%o]', buffer);
    //   if (done) {
    //     break;
    //   }
    //   offset += view.byteLength;
    // }
  
    // // this._zitiContext.logger.trace('ZitiWASMTLSConnection._readInto: returning buffer [%o]', buffer);
    // return buffer;
  }
  


}

// Export class
export {
  ZitiWASMTLSConnection
}
