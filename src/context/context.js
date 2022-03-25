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
import { defaultOptions } from './options'

import { LibCrypto } from '@openziti/libcrypto-js'
import { ZitiBrowzerEdgeClient } from '@openziti/ziti-browzer-edge-client'

 
/**
 *    ZitiContext
 */
class ZitiContext {

  /**
   *  ctor
   * 
   *  @param {Options} [options]
   */
  constructor(options) {

    this._initialized = false;

    let _options = flatOptions(options, defaultOptions);

    this.logger = _options.logger;

    this._libCrypto = new LibCrypto();
    this._libCryptoInitialized = false;

    this._network_sessions = new Map();
    this._services = new Map();
    this._channels = new Map();
    this._channelSeq = 0;
    this._connSeq = 0;

    // this._mutex = new Mutex.Mutex();
    // this._connectMutexWithTimeout = withTimeout(new Mutex.Mutex(), 30000);

  }

  get libCrypto () {
    return this._libCrypto;
  }


  /**
   * 
   */
  async initialize() {

    if (this._initialized) throw Error("Already initialized; Cannot call .initialize() twice on instance.");

    this.logger.trace(`_libCrypto.initialize starting`);

    await this._libCrypto.initialize(); 

    this._initialized = true;    

    this.logger.trace(`_libCrypto.initialize completed`);
  }

  /**
   * 
   * @param {*} options 
   * @returns ZitiContext
   */
  createZitiBrowzerEdgeClient (options) {

    if (this._zitiBrowzerEdgeClient !== undefined) throw Error("Already have a ZitiBrowzerEdgeClient; Cannot call .createZitiBrowzerEdgeClient() twice on instance.");

    this._zitiBrowzerEdgeClient = new ZitiBrowzerEdgeClient(Object.assign({
    }, options))

    return this._zitiBrowzerEdgeClient;
  }


  /**
   * 
   */
  generateECKey() {

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    const privateKeyPEM = this._libCrypto.generateECKey({});

    return privateKeyPEM;
  }
  

}

// Export class
export default ZitiContext

