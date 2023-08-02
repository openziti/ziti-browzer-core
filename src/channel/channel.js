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

import { flatOptions } from '../utils/flat-options'
import { defaultOptions } from './channel-options'
import { ZitiConnections } from './connections';
import { ZitiWASMTLSConnection } from './wasm-tls-connection';
import { Header } from './header';
import { ZitiWebSocket } from '../websocket/websocket';
import { ZitiSocket } from '../http/ziti-socket';
import { Messages } from './messages';
import { ZitiEdgeProtocol } from '../channel/protocol';
import throwIf from '../utils/throwif';
import {
  appendBuffer,
  toUTF8Array,
  sumBy,
  concatTypedArrays
} from '../utils/utils';

import { isUndefined, isNull, isEqual, forEach } from 'lodash-es';
import { Mutex, withTimeout, Semaphore } from 'async-mutex';
import { Buffer } from 'buffer';
import { v4 as uuidv4 } from 'uuid';
import { parse as uuidParse } from 'uuid';
import { stringify as uuidStringify } from 'uuid';

//TODO: this breaks the build at the moment... figure out why!
import sodium  from 'libsodium-wrappers';

import PromiseController from 'promise-controller';
import formatMessage from 'format-message';

formatMessage.setup({
  // locale: 'en', // what locale strings should be displayed
  // missingReplacement: '!!NOT TRANSLATED!!', // use this when a translation is missing instead of the default message
  missingTranslation: 'ignore', // don't console.warn or throw an error when a translation is missing
})

 
/**
 *    ZitiChannel
 */
class ZitiChannel {

  /**
   * 
   */
  constructor(options) {

    let _options = flatOptions(options, defaultOptions);

    this._session_token = _options.session_token;
    this._network_session_token = _options.network_session_token;

    this._zitiContext = _options.zitiContext;

    this._id = this._zitiContext.getNextChannelId();

    this._data = _options.data;

    this._timeout = _options.timeout;
    this._helloTimeout = _options.helloTimeout;

    this._state = ZitiEdgeProtocol.conn_state.Initial;

    this._msgSeq = -1;

    this._edgeRouter = _options.edgeRouter;
    this._edgeRouterHost = this._edgeRouter.hostname;

    this._connections = new ZitiConnections();

    this._zws = new ZitiWebSocket( this._zitiContext.getEdgeRouterURL(this._edgeRouter) + '/ws' , { 
      zitiContext: this._zitiContext,
    });
    this._callerId = "ws:";

    this._zws.onMessage.addListener(this._recvFromWire, this);

    this._zws.onClose.addListener(this._recvClose, this);

    this._zws.onSend.addListener(this._recvSend, this);

    this._createHelloController();

    // Set the maximum timestamp
    this._helloCompletedTimestamp = new Date(8640000000000000); // http://www.ecma-international.org/ecma-262/5.1/#sec-15.9.1.1

    this._messages = new Messages({ zitiContext: this._zitiContext, channel: this });

    this._view_version = new Uint8Array(new ArrayBuffer(4));
    this._view_version.set(ZitiEdgeProtocol.VERSION, 0);

    this._mutex = withTimeout(new Mutex(), 2 * 1000);

    this._hdrIdNameMap = new Map();
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.ConnectionId,   'ConnectionId');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.ReplyFor,       'ReplyFor');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.ResultSuccess,  'ResultSuccess');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.HelloListener,  'HelloListener');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.HelloVersion,   'HelloVersion');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.ConnId,         'ConnId');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.SeqHeader,      'SeqHeader');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.SessionToken,   'SessionToken');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.PublicKey,      'PublicKey');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.Cost,           'Cost');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.Precedence,     'Precedence');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.TerminatorIdentity,       'TerminatorIdentity');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.TerminatorIdentitySecret, 'TerminatorIdentitySecret');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.CallerId,       'CallerId');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.CryptoMethod,   'CryptoMethod');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.Flags,          'Flags');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.AppData,        'AppData');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.RouterProvidedConnId, 'RouterProvidedConnId');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.HealthStatus,         'HealthStatus');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.ErrorCode,            'ErrorCode');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.Timestamp,            'Timestamp');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.TraceHopCount,        'TraceHopCount');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.TraceHopType,         'TraceHopType');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.TraceHopId,           'TraceHopId');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.TraceSourceRequestId, 'TraceSourceRequestId');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.TraceError,           'TraceError');
    this._hdrIdNameMap.set(ZitiEdgeProtocol.header_id.UUID,                 'UUID');
  }

  get zitiContext() {
    return this._zitiContext;
  }

  get id() {
    return this._id;
  }

  get tlsConn() {
    return this._tlsConn;
  }

  get data() {
    return this._data;
  }

  get state() {
    return this._state;
  }
  set state(state) {
    this._state = state;
  }

  getAndIncrementSequence() {
    return this._msgSeq++;
  }

  get edgeRouterHost() {
    return this._edgeRouterHost;
  }

  get helloCompletedTimestamp() {
    return this._helloCompletedTimestamp;
  }

  get isHelloCompleted() {
    return Boolean(this._helloCompleted);
  }

  /**
   * 
   */
  _createHelloController() {
    const helloTimeout = this._helloTimeout || this._timeout;
    this._helloing = new PromiseController({
      timeout: helloTimeout,
      timeoutReason: `Can't complete 'Hello' within allowed timeout: ${helloTimeout} ms.`
    });
  }

  /**
   * Remain in lazy-sleepy loop until tlsConn has completed its TLS handshake.
   * 
   */
  async awaitTLSHandshakeComplete() {
    let self = this;
    return new Promise((resolve) => {
      (function waitForTLSHandshakeComplete() {
        if (!self._tlsConn.connected) {
          self._zitiContext.logger.trace('ZitiChannel.awaitTLSHandshakeComplete() wasmFD[%d] TLS handshake still not complete', self._tlsConn.wasmFD);
          setTimeout(waitForTLSHandshakeComplete, 100);  
        } else {
          self._zitiContext.logger.trace('ZitiChannel.awaitTLSHandshakeComplete() wasmFD[%d] TLS handshake complete', self._tlsConn.wasmFD);
          // TODO: investigate why this shows 'fail' when in fact it was 'success'
          // let result = self._tlsConn.ssl_get_verify_result();
          // if (result !== 1) {
          //   self._zitiContext.logger.error('tlsConn for ch[%d] fails TLS verification', self.id);
          // }
          return resolve();
        }
      })();
    });
  }

  /**
   * Do Hello handshake between this channel and associated Edge Router.
   * 
   */
  async hello() {

    this._zitiContext.logger.trace('ZitiChannel.hello entered for ch[%o]', this);

    await this._zws.open();

    this._zitiContext.logger.trace('ZitiChannel.hello _zws.open completed for ch[%o]', this);

    if (this.isHelloCompleted) {
      this._zitiContext.logger.trace('Hello handshake was previously completed');
      return new Promise( async (resolve) => {
        resolve( {channel: this, data: null});
      });
    }

    if (isEqual(this._callerId, "ws:")) {

      this._tlsConn = new ZitiWASMTLSConnection({
        zitiContext: this._zitiContext,
        ws: this._zws,
        ch: this,
        datacb: this._recvFromWireAfterDecrypt
      });
      this._tlsConn.setWASMFD(this._zitiContext.addWASMFD(this._tlsConn));

      await this._tlsConn.pullKeyPair();
  
      await this._tlsConn.create();

      this._zitiContext.logger.debug('initiating TLS handshake');

      await this._tlsConn.handshake();

      await this.awaitTLSHandshakeComplete();

      this._zitiContext.logger.debug('TLS handshake complete');

    }

    this._zitiContext.logger.debug('initiating message: ZitiEdgeProtocol.content_type.HelloType: ', ZitiEdgeProtocol.header_type.StringType);
    let uuid = uuidv4();

    let headers = [
      new Header( ZitiEdgeProtocol.header_id.SessionToken, { 
        headerType: ZitiEdgeProtocol.header_type.StringType, 
        headerData: this._session_token 
      }),
      new Header( ZitiEdgeProtocol.header_id.CallerId, { 
        headerType: ZitiEdgeProtocol.header_type.StringType, 
        headerData: this._callerId 
      }),
      new Header( ZitiEdgeProtocol.header_id.UUID, { 
        headerType: ZitiEdgeProtocol.header_type.Uint8ArrayType, 
        headerData: uuidParse(uuid)
      })
    ]; 

    let sequence = this.getAndIncrementSequence();

    let msg = await this.sendMessage( ZitiEdgeProtocol.content_type.HelloType, headers, null, { 
      sequence: sequence,
    });

    this._helloCompletedTimestamp = Date.now();
    this._helloCompleted = true;
    this.state = (ZitiEdgeProtocol.conn_state.Connected);
    this._zitiContext.logger.debug('ch[%d] Hello handshake to Edge Router [%s] completed at timestamp[%o]', this._id, this._edgeRouterHost, this._helloCompletedTimestamp);

    return new Promise( async (resolve) => {
      resolve( {channel: this, data: null});
    });

  }

  /**
   * Connect specified Connection to associated Edge Router.
   * 
   */
  async connect(conn) {

    const self = this;
    return new Promise( async (resolve, reject) => {
    
      self._zitiContext.logger.debug('initiating Connect to Edge Router [%s] for conn[%d]', this._edgeRouterHost, conn.id);
  
      await sodium.ready;
    
      let keypair = sodium.crypto_kx_keypair();
  
      conn.keypair = (keypair);
  
      let sequence = this.getAndIncrementSequence();
      let uuid = uuidv4();

      let headers = [
    
        new Header( ZitiEdgeProtocol.header_id.ConnId, {
          headerType: ZitiEdgeProtocol.header_type.IntType,
          headerData: conn.id
        }),
  
        new Header( ZitiEdgeProtocol.header_id.SeqHeader, { 
          headerType: ZitiEdgeProtocol.header_type.IntType, 
          headerData: 0 
        }),
    
        new Header( ZitiEdgeProtocol.header_id.UUID, { 
          headerType: ZitiEdgeProtocol.header_type.Uint8ArrayType, 
          headerData: uuidParse(uuid)
        }),
  
      ];

      if (conn.encrypted) {  // if connected to a service that has 'encryptionRequired'

        headers.push(
        
          new Header( ZitiEdgeProtocol.header_id.PublicKey, { 
            headerType: ZitiEdgeProtocol.header_type.Uint8ArrayType, 
            headerData: keypair.publicKey
          })
    
        );
      }

      if (!isUndefined(conn.appData)) {  // if serviceConnectAppData is present

        headers.push(
        
          new Header( ZitiEdgeProtocol.header_id.AppData, { 
            headerType: ZitiEdgeProtocol.header_type.StringType, 
            headerData: JSON.stringify(conn.appData)
          })
    
        );
      }

      conn.state = (ZitiEdgeProtocol.conn_state.Connecting);
  
      self._zitiContext.logger.debug('about to send Connect to Edge Router [%s] for conn[%d]', conn.channel.edgeRouterHost, conn.id);
  
      let msg = await self.sendMessage( ZitiEdgeProtocol.content_type.Connect, headers, self._network_session_token, { 
          conn: conn,
          sequence: sequence,
        } 
      );

      self._zitiContext.logger.debug('connect() calling _recvConnectResponse() for conn[%d]', conn.id);

      await self._recvConnectResponse(msg.data, conn);
    
      resolve();
  
    });
  }

  /**
   * Close specified Connection to associated Edge Router.
   * 
   */
  async close(conn) {

    const self = this;
    return new Promise( async (resolve, reject) => {
    
      self._zitiContext.logger.debug('initiating Close to Edge Router [%s] for conn[%d]', this._edgeRouterHost, conn.id);
  
      let sequence = conn.getAndIncrementSequence();
      let uuid = uuidv4();

      let headers = [
    
        new Header( ZitiEdgeProtocol.header_id.ConnId, {
          headerType: ZitiEdgeProtocol.header_type.IntType,
          headerData: conn.id
        }),
  
        new Header( ZitiEdgeProtocol.header_id.SeqHeader, { 
          headerType: ZitiEdgeProtocol.header_type.IntType, 
          headerData: sequence
        }),
    
        new Header( ZitiEdgeProtocol.header_id.UUID, { 
          headerType: ZitiEdgeProtocol.header_type.Uint8ArrayType, 
          headerData: uuidParse(uuid)
        }),
  
      ];
    
      self._zitiContext.logger.debug('about to send Close to Edge Router [%s] for conn[%d]', conn.channel.edgeRouterHost, conn.id);
  
      let msg = await self.sendMessage( ZitiEdgeProtocol.content_type.StateClosed, headers, self._network_session_token, { 
          conn: conn,
          sequence: sequence,
        } 
      );

      self._zitiContext.logger.debug('close() completed with response[%o]', msg);

      conn.state = (ZitiEdgeProtocol.conn_state.Closed);
    
      resolve();
  
    });
  }

  /**
   * Receives response from Edge 'Connect' message.
   * 
   */
  async _recvConnectResponse(msg, expectedConn) {

    // let buffer = await msg.arrayBuffer();
    let buffer = await msg.buffer;
    let contentTypeView = new Int32Array(buffer, 4, 1);
    let contentType = contentTypeView[0];
    let sequenceView = new Int32Array(buffer, 8, 1);
    let sequence = sequenceView[0];
    let connId = await this._messageGetConnId(msg);
    let conn = this._connections._getConnection(connId);
    throwIf(isUndefined(conn), formatMessage('Conn not found. Seeking connId { actual }', { actual: connId}) );
    if (!isEqual(conn.id, expectedConn.id)) {
      this._zitiContext.logger.error("_recvConnectResponse() actual conn[%d] expected conn[%d]", conn.id, expectedConn.id);
    }

    this._zitiContext.logger.debug("ConnectResponse contentType[%d] seq[%d] received for conn[%d]", contentType, sequence, conn.id);

    switch (contentType) {

      case ZitiEdgeProtocol.content_type.StateClosed:

        this._zitiContext.logger.warn("conn[%d] failed to connect on ch[%d]", conn.id, this.id);
        conn.state = (ZitiEdgeProtocol.conn_state.Closed);

        this._zitiContext.emit('channelConnectFailEvent', {
          serviceName: expectedConn.data.serviceName
        });
        break;

      case ZitiEdgeProtocol.content_type.StateConnected:

        if (conn.state == ZitiEdgeProtocol.conn_state.Connecting) {
          this._zitiContext.logger.debug("conn[%d] connected", conn.id);

          if (conn.encrypted) {  // if connected to a service that has 'encryptionRequired'

            await this._establish_crypto(conn, msg);
            this._zitiContext.logger.debug("establish_crypto completed for conn[%d]", conn.id);

            await this._send_crypto_header(conn);
            this._zitiContext.logger.debug("send_crypto_header completed for conn[%d]", conn.id);

          }

          conn.state = (ZitiEdgeProtocol.conn_state.Connected);
        }

        else if (conn.state == ZitiEdgeProtocol.conn_state.Closed || conn.state == ZitiEdgeProtocol.conn_state.Timedout) {
          this._zitiContext.logger.warn("received connect reply for closed/timedout conne[%d]", conn.id);
          // ziti_disconnect(conn);
        }
        break;

      default:
        this._zitiContext.logger.error("unexpected content_type[%d] conn[%d]", contentType, conn.id);
        // ziti_disconnect(conn);
    }

  }

  /**
   * 
   */
  async _establish_crypto(conn, msg) {

    this._zitiContext.logger.debug("_establish_crypto(): entered for conn[%d]", conn.id);

    let result = await this._messageGetBytesHeader(msg, ZitiEdgeProtocol.header_id.PublicKey);
    let peerKey = result.data;
    this._zitiContext.logger.debug("_establish_crypto(): peerKey is: ", peerKey);

    if (peerKey == undefined) {
      this._zitiContext.logger.debug("_establish_crypto(): did not receive peer key. connection[%d] will not be encrypted: ", conn.id);
      conn.encrypted = false;
      return;
    }

    if (conn.state == ZitiEdgeProtocol.conn_state.Connecting) {

      let keypair = conn.keypair;

      let results = sodium.crypto_kx_client_session_keys(keypair.publicKey, keypair.privateKey, peerKey);

      conn.sharedRx = (results.sharedRx);
      conn.sharedTx = (results.sharedTx);

    } else {
      this._zitiContext.logger.error("_establish_crypto(): cannot establish crypto while connection is in %d state: ", conn.state);
    }

  }

  /**
   * Receives response from Edge 'Data' message where we sent the Crypto header.
   * 
   */
  async _recvCryptoResponse(msg) {

    let connId = await this._messageGetConnId(msg);
    this._zitiContext.logger.debug("_recvCryptoResponse(): entered for conn[%d]", connId);
    let conn = this._connections._getConnection(connId);
    throwIf(isUndefined(conn), formatMessage('Conn not found. Seeking connId { actual }', { actual: connId}) );

    //
    let buffer = await msg.buffer;
    let headersLengthView = new Int32Array(buffer, 12, 1);
    let headersLength = headersLengthView[0];
    var bodyView = new Uint8Array(buffer, 20 + headersLength);

    let state_in = sodium.crypto_secretstream_xchacha20poly1305_init_pull(bodyView, conn.sharedRx);
    
    conn.crypt_i = (state_in);

    // Indicate that subsequent sends on this connection should be encrypted
    conn.encrypted = true;

    // Unblock writes to the connection now that we have sent the crypto header
    conn.cryptoEstablishComplete = true;

    this._zitiContext.logger.debug("_recvCryptoResponse(): setCryptoEstablishComplete for conn[%d]", connId);

  }

  /**
   * Remain in lazy-sleepy loop until specified connection's crypto handshake is complete.
   * 
   * @param {*} conn 
   */
  awaitConnectionCryptoEstablishComplete(conn) {
    return new Promise((resolve) => {
      (function waitForCryptoEstablishComplete() {
        if (conn.cryptoEstablishComplete) {
          conn.zitiContext.logger.debug('Connection [%d] now Crypto-enabled with Edge Router', conn.id);
          return resolve();
        }
        conn.zitiContext.logger.debug('awaitConnectionCryptoEstablishComplete() conn[%d] still not yet CryptoEstablishComplete', conn.id);
        setTimeout(waitForCryptoEstablishComplete, 100);
      })();
    });
  }

  /**
   * 
   */
  async _send_crypto_header(conn) {

    const self = this;
    return new Promise( async (resolve, reject) => {

      let results = sodium.crypto_secretstream_xchacha20poly1305_init_push( conn.sharedTx );

      conn.crypt_o = (results);

      let sequence = conn.getAndIncrementSequence();
      let uuid = uuidv4();

      let headers = [

        new Header( ZitiEdgeProtocol.header_id.ConnId, {
          headerType: ZitiEdgeProtocol.header_type.IntType,
          headerData: conn.id
        }),

        new Header( ZitiEdgeProtocol.header_id.SeqHeader, { 
          headerType: ZitiEdgeProtocol.header_type.IntType, 
          headerData: sequence 
        }),

        new Header( ZitiEdgeProtocol.header_id.UUID, { 
          headerType: ZitiEdgeProtocol.header_type.Uint8ArrayType, 
          headerData: uuidParse(uuid)
        }),

      ];    

      self._zitiContext.logger.debug('_send_crypto_header(): conn[%d] sending Data [%o]', conn.id, conn.crypt_o.header);

      let msg = await self.sendMessage( ZitiEdgeProtocol.content_type.Data, headers, conn.crypt_o.header, {
          conn: conn,
          sequence: sequence,
        }
      );

      self._zitiContext.logger.debug('_send_crypto_header() calling _recvCryptoResponse() for conn[%d]', conn.id);
      await self._recvCryptoResponse(msg.data, conn);

      resolve();

    });
  }

  /**
   * Write data over specified Edge Router connection.
   *
   * @returns {Promise}
   */
  async write(conn, data) {

    if (!isEqual(conn.state, ZitiEdgeProtocol.conn_state.Closed)) {

      let sequence = conn.getAndIncrementSequence();
      let uuid = uuidv4();

      let headers = [
        new Header( ZitiEdgeProtocol.header_id.ConnId, {
          headerType: ZitiEdgeProtocol.header_type.IntType,
          headerData: conn.id
        }),
        new Header( ZitiEdgeProtocol.header_id.SeqHeader, { 
          headerType: ZitiEdgeProtocol.header_type.IntType, 
          headerData: sequence 
        }),
        new Header( ZitiEdgeProtocol.header_id.UUID, { 
          headerType: ZitiEdgeProtocol.header_type.Uint8ArrayType, 
          headerData: uuidParse(uuid)
        })  
      ];

      this.sendMessageNoWait( ZitiEdgeProtocol.content_type.Data, headers, data, { conn: conn, sequence: sequence });
    }
  }

  /**
   * Sends message and waits for response.
   *
   * @param {String|Number} contentType
   * @param {[Header]} headers
   * @param {*} body
   * @param {Object} [options]
   * @returns {Promise}
   */
  sendMessage(contentType, headers, body, options = {}) {
    const timeout = options.timeout !== undefined ? options.timeout : this._timeout;
    let messageId;
    if (!isUndefined(options.sequence)) {
      messageId = options.sequence;
    } else if (!isUndefined(this._sequence)) {
      messageId = this._sequence;
    } 
    throwIf(isUndefined(messageId), formatMessage('messageId is undefined', { } ) );
    
    let messagesQueue = this._messages;
    let conn;
    if (!isUndefined(options.conn)) {
      conn = options.conn;
      messagesQueue = options.conn.messages;
    }

    this._zitiContext.logger.debug("send -> conn[%o] seq[%o] contentType[%o] body[%s]", (conn ? conn.id : 'n/a'), messageId, contentType, (body ? body.toString() : 'n/a'));

    return messagesQueue.create(messageId, () => {
      this._sendMarshaled(contentType, headers, body, options, messageId);
    }, timeout);
  }

  /**
   * Sends message and does not wait for response.
   *
   * @param {String|Number} contentType
   * @param {[Header]} headers
   * @param {*} body
   * @param {Object} [options]
   * @returns {Promise}
   */
  sendMessageNoWait(contentType, headers, body, options = {}) {
    const timeout = options.timeout !== undefined ? options.timeout : this._timeout;
    const messageId = options.sequence || this._sequence;
    // this._zitiContext.logger.debug("send (no wait) -> conn[%o] seq[%o] contentType[%o]", 
    //   (options.conn ? options.conn.id : 'n/a'), 
    //   messageId, 
    //   contentType, 
    //   (body ? body.toString() : 'n/a'));

    this._zitiContext.logger.debug("send (no wait) -> conn[%o] seq[%o] contentType[%o] bodyLen[%o] ", 
      (options.conn ? options.conn.id : 'n/a'), 
      messageId, contentType, 
      (body ? body.length : 'n/a')
      ,
      (body ? body.toString() : 'n/a')
      );

    this._sendMarshaled(contentType, headers, body, options, messageId);
  }

  /**
   * Marshals message into binary wire format and sends to the Edge Router.
   *
   * @param {String|Number} contentType
   * @param {[Header]} headers
   * @param {*} body
   * @param {Object} [options]
   * @param {int} messageId
   */
  _sendMarshaled(contentType, headers, body, options, messageId) {

    let dataToMarshal = body;

    // this._zitiContext.logger.trace("_sendMarshaled -> dataToMarshal[%o] ", dataToMarshal);

    let doSodiumEncryption = true;
    let doMarshalMessage = true;

    let conn = options.conn;

    if (!isUndefined(conn) && conn._socket.innerTLSSocket) {
      this._zitiContext.logger.trace("_sendMarshaled -> conn._socket.innerTLSSocket._connected[%o] ", conn._socket.innerTLSSocket._connected);
      this._zitiContext.logger.trace("_sendMarshaled -> conn._socket.innerTLSSocket._sendingEncryptedData[%o] ", conn._socket.innerTLSSocket._sendingEncryptedData);
      if (conn._socket.innerTLSSocket._connected) {
        doSodiumEncryption = false;   // assume innerTLSSocket hasn't yet done its TLS encryption of the message data
        doMarshalMessage = false;     // assume innerTLSSocket hasn't yet done its TLS encryption of the message data
        this._zitiContext.logger.trace(`_sendMarshaled 1 doSodiumEncryption ${doSodiumEncryption}`);
        if (!isUndefined(conn._socket.innerTLSSocket._sendingEncryptedData)) {
          if (conn._socket.innerTLSSocket._sendingEncryptedData) {
            doSodiumEncryption = true;  // now that innerTLSSocket has done its TLS encryption of the data, allow the sodium encryption to wrap it
            doMarshalMessage = true;    // now that innerTLSSocket has done its TLS encryption of the data, ensure we marshal the data for xmit to ER
            this._zitiContext.logger.trace(`_sendMarshaled 2 doSodiumEncryption ${doSodiumEncryption}`);
          }
        }
      }
    }

    if (contentType != ZitiEdgeProtocol.content_type.Data) {
      doMarshalMessage = true;  // we always marshal non-Data msgs
    }

    if (doMarshalMessage) {

      if (contentType != ZitiEdgeProtocol.content_type.HelloType) {

        let connId;
        forEach(headers, function(header) {
          if (header.getId() == ZitiEdgeProtocol.header_id.ConnId) {
            connId = header.getData();
          }
        });
        throwIf(isUndefined(connId), formatMessage('Cannot find ConnId header', { } ) );

        let conn = this._connections._getConnection(connId);
        throwIf(isUndefined(conn), formatMessage('Conn not found. Seeking connId { actual }', { actual: connId}) );

        if (conn.encrypted && conn.cryptoEstablishComplete && doSodiumEncryption) {  // if connected to a service that has 'encryptionRequired'

          this._zitiContext.logger.trace("_sendMarshaled doing sodium encryption");

          let [state_out, header] = [conn.crypt_o.state, conn.crypt_o.header];

          let encryptedData = sodium.crypto_secretstream_xchacha20poly1305_push(
            state_out,
            body,
            null,
            sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

          dataToMarshal = encryptedData;
          this._zitiContext.logger.trace("_sendMarshaled -> encrypted dataToMarshal len[%o] ", dataToMarshal.byteLength);
        }
      }

      const wireData = this._marshalMessage(contentType, headers, dataToMarshal, options, messageId);
      this._zitiContext.logger.trace("_sendMarshaled -> wireDataLen[%o] ", wireData.byteLength);

      // this._dumpHeaders(' -> ', wireData);

      // Inject the listener if specified
      if (options.listener !== undefined) {
        this._zws.onMessage.addOnceListener(options.listener, this);
      }

      // If connected to a WS edge router
      if (isEqual(this._callerId, "ws:")) {
        this._tlsConn.tls_write(wireData, options.conn);
      }
      else {
        this._zws.send(wireData);
      }
    }
    else {

      this._zitiContext.logger.trace("_sendMarshaled -> bypassing marshaling until innerTLSSocket completes encryption pass");

      this._tlsConn.tls_write(body.buffer, options.conn);
    }
  }

  /**
   * Marshals message into binary wire format.
   *
   * @param {String|Number} contentType
   * @param {[Header]} headers
   * @param {*} body
   * @param {Object} [options]
   * @returns {byte[]}   
   */
  _marshalMessage(contentType, headers, body, options, messageId) {

    // wire-protocol: message-section
    let buffer_message_section = new ArrayBuffer(
      4   // Version
      +4  // ContentType  (offset 4)
      +4  // Sequence     (offset 8)
      +4  // hdrs-len     (offset 12)
      +4  // body-len     (offset 16)
    );
    
    // wire-protocol: Version
    let view_message_section = new Uint8Array(buffer_message_section);
    view_message_section.set(
      ZitiEdgeProtocol.VERSION, 
      0 // Offset 0
    );
    
    var bytes = new Buffer(4);
    
    // wire-protocol: ContentType
    bytes.writeUInt32LE(contentType, 0);
    view_message_section.set(
      bytes, 
      4 // Offset 4
    );
    
    bytes = new Buffer(4);
    
    // wire-protocol: Sequence
    bytes.writeInt32LE(messageId, 0);
    view_message_section.set(
      bytes, 
      8 // Offset 8
    );
        
    bytes = new Buffer(4);
  
    let hdrsLen = sumBy(headers, function (header) {
      return header.getLength(); 
    });

    // wire-protocol: hdrs-len
    bytes.writeInt32LE(hdrsLen, 0);
    view_message_section.set(
      bytes, 
      12  // Offset 12
    );
    
    bytes = new Buffer(4);
     
    // wire-protocol: body-len
    let bodyLength = 0;
    if (!isNull(body)) {
      bodyLength = body.length;
    }

    bytes.writeUInt32LE(bodyLength, 0);
    view_message_section.set(
      bytes, 
      16  // Offset 16
    );
    
    // wire-protocol: headers
    let buffer_headers_section = new ArrayBuffer(hdrsLen);
    let view_headers_section = new Uint8Array(buffer_headers_section);
    let view_headers_section_offset = 0;
    forEach(headers, function(header) {
      view_headers_section.set(header.getBytesForWire(), view_headers_section_offset);
      view_headers_section_offset += header.getLength(); 
    });
    
    
    // wire-protocol: body
    let buffer_body_section = new ArrayBuffer(bodyLength);
    if (bodyLength > 0) {
      let view_body_section = new Uint8Array(buffer_body_section);
      let body_bytes;
      if (typeof body === 'string') {
        body_bytes = toUTF8Array(body);
      } else {
        body_bytes = body;
      }
      let bytesBuffer = Buffer.from(body_bytes);
      view_body_section.set(bytesBuffer, 0);
    }
    
    // Put it all together
    // this._zitiContext.logger.trace("_marshalMessage -> buffer_message_section Len[%o] ", buffer_message_section.byteLength);
    // this._zitiContext.logger.trace("_marshalMessage -> buffer_headers_section Len[%o] ", buffer_headers_section.byteLength);
    // this._zitiContext.logger.trace("_marshalMessage -> buffer_body_section Len[%o] ", buffer_body_section.byteLength);
    let buffer_combined = appendBuffer(buffer_message_section, buffer_headers_section);
    buffer_combined = appendBuffer(buffer_combined, buffer_body_section);
    let view_combined = new Uint8Array(buffer_combined);
  
    return view_combined.buffer;
  }

  /**
   * Receives a send event from the Websocket.
   * 
   * @param {*} data 
   */
  async _recvSend(data) {
    if (!isUndefined(this._zws)) {
      if (!isNull(this._zws._ws)) {
        this._zitiContext.logger.debug('_recvSend -> sentLen[%o] bufferedLen[%o]', data.byteLength, this._zws._ws.bufferedAmount);
      }
    }
  }

  /**
   * Receives a close event from the Websocket.
   * 
   * @param {*} data 
   */
  async _recvClose(data) {

    this._zitiContext.logger.warn('channel._recvClose -> ER[%s]', this._edgeRouterHost);

    this._zitiContext.closeChannelByEdgeRouter( this._edgeRouterHost );

  }

  /**
   * Receives a message from the Edge Router.
   * 
   * @param {*} data //Blob
   */
  async _recvFromWire(data) {
    let buffer = await data.arrayBuffer();
    this._zitiContext.logger.debug("_recvFromWire <- data len[%o]", buffer.byteLength);
    await this._tlsConn.process(buffer);
  }

  /**
   * Receives un-encrypted binary data from the Edge Router (which is either an entire edge protocol message, or a fragment thereof)
   * 
   * @param ArrayBuffer data 
   */
  async _recvFromWireAfterDecrypt(ch, data) {

    let buffer = data;

    if (!isUndefined(ch._partialMessage)) {  // if we are awaiting rest of a partial msg to arrive, append this chunk onto the end, then proceed
      let dataView = new Uint8Array(data);
      ch._partialMessage = concatTypedArrays(ch._partialMessage, dataView);
      buffer = ch._partialMessage.buffer.slice(0);
    } 

    let versionView = new Uint8Array(buffer, 0, 4);
    throwIf(!isEqual(versionView[0], ch._view_version[0]), formatMessage('Unexpected message version. Got { actual }, expected { expected }', { actual: versionView[0], expected:  ch._view_version[0]}) );

    let headersLengthView = new Int32Array(buffer, 12, 1);
    let headersLength = headersLengthView[0];

    let bodyLengthView = new Int32Array(buffer, 16, 1);
    let bodyLength = bodyLengthView[0];

    let msgLength = ( 20 + headersLength + bodyLength );

    if (isEqual(msgLength, buffer.byteLength)) {  // if entire edge message is present, proceed with unmarshaling effort

      ch._partialMessage = undefined;
      
      ch._tryUnmarshal(buffer);

    } else if (msgLength < buffer.byteLength) {  // if entire edge message is present, proceed with unmarshaling effort

      ch._partialMessage = undefined;
      
      ch._tryUnmarshal(buffer);

    } else {

      ch._partialMessage = new Uint8Array(buffer);

      if (buffer.byteLength > 20) { // if we have a portion of the data section of the edge message 
        ch._zitiContext.logger.debug("Only [%o] of msgLength [%o] received; will await rest of fragments before unmarshaling", buffer.byteLength, msgLength);
      }
    }
  }

  /**
   * Unmarshals binary from the wire into a message
   * 
   * @param {*} data 
   */
  async _tryUnmarshal(data) {

    let buffer = data;

    let versionView = new Uint8Array(buffer, 0, 4);
    throwIf(!isEqual(versionView[0], this._view_version[0]), formatMessage('Unexpected message version. Got { actual }, expected { expected }', { actual: versionView[0], expected:  this._view_version[0]}) );

    let contentTypeView = new Int32Array(buffer, 4, 1);
    let contentType = contentTypeView[0];

    let sequenceView = new Int32Array(buffer, 8, 1);
    let responseSequence = sequenceView[0];

    let headersLengthView = new Int32Array(buffer, 12, 1);
    let headersLength = headersLengthView[0];

    let bodyLengthView = new Int32Array(buffer, 16, 1);
    let bodyLength = bodyLengthView[0];

    this._zitiContext.logger.trace("recv <- contentType[%o] seq[%o] hdrLen[%o] bodyLen[%o]", contentType, responseSequence, headersLength, bodyLength);

    // this._dumpHeaders(' <- ', buffer);
    var bodyView = new Uint8Array(buffer, 20 + headersLength);

    let connId;
    let conn;
    let replyForView;
    let haveResponseSequence = false;

    const release = await this._mutex.acquire();

    let zeroByteData = false;

    /**
     *  First Data msg for a new connection needs special handling
     */
    if (contentType == ZitiEdgeProtocol.content_type.Data) {
      connId = await this._messageGetConnId(data);
      if (!isUndefined(connId)) {
        conn = this._connections._getConnection(connId);
        if (!isUndefined(conn)) {
          if (isEqual(conn.state, ZitiEdgeProtocol.conn_state.Connecting)) {
            let result = await this._messageGetBytesHeader(data, ZitiEdgeProtocol.header_id.SeqHeader);
            if (!isUndefined(result)) {
              replyForView = new Int32Array(result.data, 0, 1);
              responseSequence = replyForView[0];
              haveResponseSequence = true;
              this._zitiContext.logger.debug("recv <- ReplyFor[%o] (should be for the crypto_header response)", responseSequence);
            }  
          }
        }
      }
    }


    if (!haveResponseSequence && (contentType >= ZitiEdgeProtocol.content_type.StateConnected)) {

      let result = await this._messageGetBytesHeader(data, ZitiEdgeProtocol.header_id.ReplyFor);
      if (!isUndefined(result)) {

        replyForView = new DataView( result.data.buffer.slice(result.data.byteOffset, result.data.byteLength + result.data.byteOffset) );
        responseSequence = replyForView.getInt32(0, true); // second parameter truthy == want little endian;
        this._zitiContext.logger.trace("recv <- ReplyFor[%o]", responseSequence);

      } else {

        if ( isEqual(contentType, ZitiEdgeProtocol.content_type.Data) && isEqual(bodyLength, 0) ) {

          zeroByteData = true;

          // let result = await this._messageGetBytesHeader(data, ZitiEdgeProtocol.header_id.SeqHeader);
          // replyForView = new Int32Array(result.data, 0, 1);
          // responseSequence = replyForView[0];
          this._zitiContext.logger.trace("recv <- bodyLength of ZERO for [%o]", responseSequence);

          // this._zitiContext.logger.trace("recv <- ReplyFor[%o]", 'n/a');  
          responseSequence--;
          // this._zitiContext.logger.trace("reducing seq by 1 to [%o]", responseSequence);
  
        } else {

          // this._zitiContext.logger.trace("recv <- ReplyFor[%o]", 'n/a');  
          responseSequence--;
          // this._zitiContext.logger.trace("reducing seq by 1 to [%o]", responseSequence);

        }
      }
    }


    if ((contentType >= ZitiEdgeProtocol.content_type.Connect) && (isUndefined(conn))) {
      let connId = await this._messageGetConnId(data);
      throwIf(isUndefined(connId), formatMessage('Cannot find ConnId header', { } ) );
      conn = this._connections._getConnection(connId);
      if (!zeroByteData) {
        throwIf(isUndefined(conn), formatMessage('Conn not found. Seeking connId { actual }', { actual: connId}) );
      }
    }
    
    /**
     *  Data msgs might need to be decrypted before passing along
     */
    if (contentType == ZitiEdgeProtocol.content_type.Data) {

      if (!isUndefined(conn)) {

        if (bodyLength > 0) {

          if (conn.encrypted && conn.cryptoEstablishComplete) {  // if connected to a service that has 'encryptionRequired'

            let unencrypted_data = sodium.crypto_secretstream_xchacha20poly1305_pull(conn.crypt_i, bodyView);

            if (!unencrypted_data) {
              this._zitiContext.logger.error("crypto_secretstream_xchacha20poly1305_pull failed. bodyLength[%d]", bodyLength);
            }

            try {
              let [m1, tag1] = [sodium.to_string(unencrypted_data.message), unencrypted_data.tag];
              let len = m1.length;
              if (len > 2000) {
                len = 2000;
              }
              // this._zitiContext.logger.trace("recv <- unencrypted_data (first 2000): %s", m1.substring(0, len));

              //
              // let dbgStr = m1.substring(0, len);
              // this._zitiContext.logger.trace("recv <- data (first 2000): %s", dbgStr);

            } catch (e) {   }

            bodyView = unencrypted_data.message;
          } else {
            /* debug...
            let len = bodyView.length;
            if (len > 2000) {
              len = 2000;
            }
            let dbgStr = String.fromCharCode.apply(null, bodyView).substring(0, len);
            this._zitiContext.logger.debug("recv <- data (first 2000): %s", dbgStr);
            */

            //temp debugging
            // if (dbgStr.includes("var openMe = (window.parent")) {

            //   let str = String.fromCharCode.apply(null, bodyView).substring(0, bodyView.length);

            //   // str = str.replace('var openMe = (window.parent', 'debugger; var openMe = (window.parent');

            //   if (str.indexOf( '/api/extplugins/config' ) !== -1) {
            //     debugger
            //   }

            //   this._zitiContext.logger.debug("============== DEBUG INJECT: %s", str);

            //   bodyView = new TextEncoder("utf-8").encode(str);
            
            // }

          }
        }

        // 
        let dataCallback = conn.dataCallback;
        if (!isUndefined(dataCallback)) {
          this._zitiContext.logger.debug("recv <- conn[%o] contentType[%o] seq[%o] passing body to dataCallback", conn.id, contentType, sequenceView[0]);
          dataCallback(conn, bodyView);
        }
      }
    }
    
    this._zitiContext.logger.trace("recv <- response body: ", bodyView);
    this._tryHandleResponse(conn, responseSequence, {channel: this, data: bodyView});

    release();
  }

  /**
   * 
   */
  _tryHandleResponse(conn, responseSequence, data) {

    if (!isUndefined(conn)) {
      let socket = conn.socket;
      if (!isUndefined(socket)) {
        if (socket.isWebSocket) {
          return;
        }
      }
    }


    let messagesQueue = this._messages;
    if (!isUndefined(conn)) {
      messagesQueue = conn.messages;
    }
    this._zitiContext.logger.trace("_tryHandleResponse():  conn[%d] seq[%d]", (conn ? conn.id : 'n/a'), responseSequence);
    if (!isNull(responseSequence)) {
      messagesQueue.resolve(responseSequence, data);
    } else {
      debugger
    }
  }

  /**
   * 
   */
  _getHeaderIdName(hdrId) {
    return this._hdrIdNameMap.get(hdrId);
  }
  _getHeaderData(hdrId, hdrData) {
    let buffer = Buffer.from(hdrData);
    if (isEqual(hdrId, ZitiEdgeProtocol.header_id.ConnId)) {
      let connId = buffer.readUIntLE(0, 4);
      return connId;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.ConnectionId)) {
      let connId = buffer.readUIntLE(0, 4);
      return connId;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.SeqHeader)) {
      let seqId = buffer.readUIntLE(0, 4);
      return seqId;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.ReplyFor)) {
      let replyFor = buffer.readUIntLE(0, 4);
      return replyFor;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.ResultSuccess)) {
      let resultSuccess = buffer.toString('hex');
      return resultSuccess;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.HelloVersion)) {
      let helloVersion = buffer.toString('utf8');
      return helloVersion;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.SessionToken)) {
      let sessToken = buffer.toString('utf8');
      return sessToken;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.CallerId)) {
      let callerId = buffer.toString('utf8');
      return callerId;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.UUID)) {
      let uuid = uuidStringify(buffer);
      return uuid;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.Flags)) {
      let flags = buffer.toString('hex');
      return flags;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.PublicKey)) {
      let flags = buffer.toString('hex');
      return flags;
    }
    else if (isEqual(hdrId, ZitiEdgeProtocol.header_id.AppData)) {
      let val = buffer.toString('utf8');
      return val;
    }
    else {
      let val = buffer.toString('utf8');
      return 'unknown - ' + val;
    }
  }

  /**
   * 
   */
  async _dumpHeaders(pfx, buffer) {

    var headersView = new Int32Array(buffer, 12, 1);

    let headersLength = headersView[0];
    this._zitiContext.logger.trace("_dumpHeaders: hdrsLen[%o]", headersLength);
    let headersOffset = 16 + 4;
    let ndx = 0;

    let view = new DataView(buffer);

    this._zitiContext.logger.trace("_dumpHeaders: "+pfx+"vv----------------------------------");

    for ( ; ndx < headersLength; ) {

      var _headerId = view.getInt32(headersOffset + ndx, true);
      ndx += 4;

      var _headerDataLength = view.getInt32(headersOffset + ndx, true);
      ndx += 4;

      var _headerData = new Uint8Array(buffer, headersOffset + ndx, _headerDataLength);
      ndx += _headerDataLength;

      this._zitiContext.logger.trace("hdrId[%d - %s] hdrDataLen[%d] hdrData[%o]", _headerId, this._getHeaderIdName(_headerId), _headerDataLength, this._getHeaderData(_headerId, _headerData));
    }

    this._zitiContext.logger.trace("_dumpHeaders: "+pfx+"^^----------------------------------");
  }

  /**
   * 
   */
  async _findHeader(msg, headerToFind) {

    let buffer;

    if (!isUndefined(msg.arrayBuffer)) {
      buffer = await msg.arrayBuffer();
    } else if (!isUndefined(msg.buffer)) {
      buffer = await msg.buffer;
    } else {
      buffer = msg;
    }

    var headersView = new Int32Array(buffer, 12, 1);

    let headersLength = headersView[0];
    let headersOffset = 16 + 4;
    let ndx = 0;

    let view = new DataView(buffer);

    for ( ; ndx < headersLength; ) {

      var _headerId = view.getInt32(headersOffset + ndx, true);
      ndx += 4;

      var _headerDataLength = view.getInt32(headersOffset + ndx, true);
      ndx += 4;

      var _headerData = new Uint8Array(buffer, headersOffset + ndx, _headerDataLength);
      ndx += _headerDataLength;

      if (_headerId == headerToFind) {

        let result = {
          dataLength: _headerDataLength,
          data:       _headerData,
        };

        return result;
      }
    }

    return undefined;
  }

  /**
   * 
   */
  async _messageGetBytesHeader(msg, headerToFind) {
    return await this._findHeader(msg, headerToFind);
  }

  /**
   * 
   */
  async _messageGetConnId(msg) {
    let results = await this._findHeader(msg, ZitiEdgeProtocol.header_id.ConnId);
    throwIf(results == undefined, formatMessage('No ConnId header found'));

    var length = results.data.length;
    let buffer = Buffer.from(results.data);
    var connId = buffer.readUIntLE(0, length);

    return connId;
  }

  getConnection(id) {
    return this._connections._getConnection(id);
  }


  getSocket() {
    return this._socket;
  }
  setSocket(socket) {
    this._socket = socket;
  }
  getDataCallback() {
    return this._dataCallback;
  }
  setDataCallback(fn) {
    this._dataCallback = fn;
  }

  // getEncrypted() {
  //   return this._encrypted;
  // }
  // setEncrypted(encrypted) {
  //   this._encrypted = encrypted;
  // }

  getCryptoEstablishComplete() {
    return this._cryptoEstablishComplete;
  }
  setCryptoEstablishComplete(complete) {
    this._cryptoEstablishComplete = complete;
  }

  getKeypair() {
    return this._keypair;
  }
  setKeypair(keypair) {
    this._keypair = keypair;
  }

  getSharedRx() {
    return this._sharedRx;
  }
  setSharedRx(sharedRx) {
    this._sharedRx = sharedRx;
  }

  getSharedTx() {
    return this._sharedTx;
  }
  setSharedTx(sharedTx) {
    this._sharedTx = sharedTx;
  }

  getCrypt_o() {
    return this._crypt_o;
  }
  setCrypt_o(crypt_o) {
    this._crypt_o = crypt_o;
  }

  getCrypt_i() {
    return this._crypt_i;
  }
  setCrypt_i(crypt_i) {
    this._crypt_i = crypt_i;
  }

}

// Export class
export {
  ZitiChannel
}
