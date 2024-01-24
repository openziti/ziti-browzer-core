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

/**
 * Module dependencies.
 */

 import { flatOptions } from '../utils/flat-options'
 import { defaultOptions } from './connection-options'
 import { ZitiEdgeProtocol } from './protocol';
 import { Messages } from './messages';


/**
 *    ZitiConnection
 */
 class ZitiConnection {

  /**
   * 
   */
  constructor(options) {

    let _options = flatOptions(options, defaultOptions);

    this._zitiContext = _options.zitiContext;

    this._data = _options.data;

    this._state = ZitiEdgeProtocol.conn_state.Initial;

    this._timeout = this._zitiContext.timeout;

    this._edgeMsgSeq = 1;

    this._id = this._zitiContext.getNextConnectionId();

    this._messages = new Messages({ zitiContext: this._zitiContext, conn: this });

  }

  get zitiContext() {
    return this._zitiContext;
  }

  get data() {
    return this._data;
  }

  get messages() {
    return this._messages;
  }

  get state() {
    return this._state;
  }
  set state(state) {
    this._state = state;
  }

  get id() {
    return this._id;
  }

  get appData() {
    return this._data.serviceConnectAppData;
  }

  getAndIncrementSequence() {
    let seq = this._edgeMsgSeq;
    this._edgeMsgSeq++;
    return seq;
  }

  get socket() {
    return this._socket;
  }
  set socket(socket) {
    this._socket = socket;
  }
  get dataCallback() {
    return this._dataCallback;
  }
  set dataCallback(fn) {
    this._dataCallback = fn;
  }

  get channel() {
    return this._channel;
  }
  set channel(channel) {
    this._channel = channel;
  }

  get encrypted() {
    return this._encrypted;
  }
  set encrypted(encrypted) {
    this._encrypted = encrypted;
  }

  get cryptoEstablishComplete() {
    return this._cryptoEstablishComplete;
  }
  set cryptoEstablishComplete(complete) {
    this._cryptoEstablishComplete = complete;
  }

  get keypair() {
    return this._keypair;
  }
  set keypair(keypair) {
    this._keypair = keypair;
  }

  get sharedRx() {
    return this._sharedRx;
  }
  set sharedRx(sharedRx) {
    this._sharedRx = sharedRx;
  }

  get sharedTx() {
    return this._sharedTx;
  }
  set sharedTx(sharedTx) {
    this._sharedTx = sharedTx;
  }

  get crypt_o() {
    return this._crypt_o;
  }
  set crypt_o(crypt_o) {
    this._crypt_o = crypt_o;
  }

  get crypt_i() {
    return this._crypt_i;
  }
  set crypt_i(crypt_i) {
    this._crypt_i = crypt_i;
  }

  get networkSessionToken() {
    return this._networkSessionToken;
  }

  set networkSessionToken(networkSessionToken) {
    this._networkSessionToken = networkSessionToken;
  }
}

// Export class
export {
  ZitiConnection
}
