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
      self.connected = true;
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
    self._zitiContext.logger.trace('ZitiWASMTLSConnection.read_cb(): clear data from the ER is ready  <--- [%o]', buffer);
    self._datacb(self._ch, buffer); // propagate clear data to the waiting Promise
  }

  /**
   * 
   * @param {*} data 
   */
  process(data) {
    this._zitiContext.logger.trace('process: data from the ER arrived  <--- [%o]', data);
    
    // Push it into the stream that is read by fd_read
    this._readableZitiStreamController.enqueue( new Uint8Array(data, 0) );
    
    // If the TLS handshake has completed, we'll need to do TLS-decrypt of the data, 
    // and then propagate it to the Promise that is waiting for it.
    if (this._connected) {

      // Make sure WASM knows where to callback to once data is ready
      this._read_cb = this.read_cb;

      let buffer = this._zitiContext.tls_read(this._SSL); // TLS-decrypt some data from the stream

      // Note that execution returns here _before_ data is actually read from the stream
      if (!isNull(buffer)) {
        this._zitiContext.logger.trace('dataReady: clear data from the server is ready  <--- ' );
        this._datacb(this._ch, buffer); // propagate clear data to the waiting Promise
      }
    }
  }
  
  /**
   * 
   * @param {*} wireData (not TLS-encrypted yet)
   */
   prepare(wireData) {
    this._zitiContext.logger.trace('prepare: unencrypted data is ready to be sent to the ER  ---> [%o]', wireData);
    let tlsBinaryString = Buffer.from(wireData).toString('binary')
    this._tlsClient.prepare(tlsBinaryString);
  }

  /**
   * 
   * @param {*} wireData (not TLS-encrypted yet)
   */
   tls_write(wireData) {
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.tls_write[%o] _ws[%o] unencrypted data is ready to be sent to the ER  ---> [%o]', this._uuid, this._ws, wireData);
    this._zitiContext.tls_write(this._SSL, wireData);
  }

  /**
   * 
   * @param {*} wireData (already TLS-encrypted)
   */
  fd_write(wireData) {
    this._zitiContext.logger.trace('ZitiWASMTLSConnection.fd_write[%o] _ws[%o] encrypted data is being sent to the ER  ---> [%o]', this._uuid, this._ws, wireData); 
    this._ws.send(wireData);
  }

  /**
   * 
   */
  async fd_read( len ) {
    this._zitiContext.logger.trace('fd_read: entered with len [%o]', len);
    let buffer = new ArrayBuffer( len );
    buffer = await this._readInto( buffer );
    this._zitiContext.logger.trace('fd_read: returning buffer [%o]', buffer);
    return buffer;
  }

  async _readInto(buffer) {
    let offset = 0;
  
    while (offset < buffer.byteLength) {
      this._zitiContext.logger.trace('_readInto: awaiting read');
      const { value: view, done } = await this._reader.read(new Uint8Array(buffer, offset, buffer.byteLength - offset));
      buffer = view.buffer;
      this._zitiContext.logger.trace('_readInto: added to buffer [%o]', buffer);
      if (done) {
        break;
      }
      offset += view.byteLength;
    }
  
    this._zitiContext.logger.trace('_readInto: returning buffer [%o]', buffer);
    return buffer;
  }
  


}

// Export class
export {
  ZitiWASMTLSConnection
}
