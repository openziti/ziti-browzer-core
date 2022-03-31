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
// import pjson from '../../package.json';
import { ZitiEnroller } from '../enroll/enroller';

import { LibCrypto } from '@openziti/libcrypto-js'
import { ZitiBrowzerEdgeClient } from '@openziti/ziti-browzer-edge-client'
import {Mutex, withTimeout} from 'async-mutex';
import { isUndefined, isNull } from 'lodash-es';

 
/**
 *    ZitiContext
 */
class ZitiContext {

  /**
   * 
   */
  constructor(options) {

    this._initialized = false;

    let _options = flatOptions(options, defaultOptions);

    this.logger = _options.logger;
    this.controllerApi = _options.controllerApi;

    this.updbUser = _options.updbUser;
    this.updbPswd = _options.updbPswd;

    this.sdkType = _options.sdkType;
    this.sdkVersion = _options.sdkVersion;
    this.sdkBranch = _options.sdkBranch;
    this.sdkRevision = _options.sdkRevision;

    this._libCrypto = new LibCrypto();
    this._libCryptoInitialized = false;

    this._network_sessions = new Map();
    this._services = new Map();
    this._channels = new Map();
    this._channelSeq = 0;
    this._connSeq = 0;

    this._mutex = new Mutex();
    this._connectMutexWithTimeout = withTimeout(new Mutex(), 30 * 1000);

    this._ecKey = null;
    this._privateKeyPEM = null;
    this._publicKeyPEM = null;
  }

  get libCrypto () {
    return this._libCrypto;
  }


  /**
   * 
   */
  async initialize() {

    if (this._initialized) throw Error("Already initialized; Cannot call .initialize() twice on instance.");

    this._zitiBrowzerEdgeClient = this.createZitiBrowzerEdgeClient ({
      logger: this.logger,
      controllerApi: this.controllerApi,
      domain: this.controllerApi,
    });

    this.logger.trace(`libCrypto.initialize starting`);

    await this._libCrypto.initialize();

    this._initialized = true;    

    this.logger.trace(`libCrypto.initialize completed; WASM is now available`);

    this._zitiEnroller = new ZitiEnroller ({
      logger: this.logger,
      zitiContext: this,
    });

  }

  /**
   * 
   * @param {*} options 
   * @returns ZitiContext
   */
  createZitiBrowzerEdgeClient (options) {

    let zitiBrowzerEdgeClient = new ZitiBrowzerEdgeClient(Object.assign({
    }, options))

    return zitiBrowzerEdgeClient;
  }


  /**
   * 
   */
  generateECKey() {

    this.logger.trace('ZitiContext.generateECKey() entered');

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._ecKey = this._libCrypto.generateECKey({});

    this.logger.trace('ZitiContext.generateECKey() exiting');

    return this._ecKey;
  }

  /**
   * 
   */
  freeECKey(pkey) {

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._libCrypto.freeECKey(pkey);
  }

  /**
   * 
   */
  getPrivateKeyPEM(pkey) {

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._privateKeyPEM = this._libCrypto.getPrivateKeyPEM(pkey);

    return this._privateKeyPEM;
  }

  /**
   * 
   */
  getPublicKeyPEM(pkey) {

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._publicKeyPEM = this._libCrypto.getPublicKeyPEM(pkey);

    return this._publicKeyPEM;
  }

  /**
   * 
   */
  createCertificateSigningRequest({
    key = null,
    curve = this._libCrypto.NID_secp521r1,
    compressed = this._libCrypto.POINT_CONVERSION_UNCOMPRESSED,
    version = 3,
    name = "C=US, ST=CO, L=BeaverCreek, O=OpenZiti, OU=browZer, CN=NetFoundry",
    // id = "0",
    // basicConstraints = null,
    // keyUsage = this.keyUsage,
    // extKeyUsage = this.extKeyUsage,
    // subjectAlternativeName = this.subjectAlternativeName,
    // subjectKeyIdentifier = null,
  }) {

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._csrPEM = this._libCrypto.createCertificateSigningRequest({
      key: key,
      curve: curve,
      compressed: compressed,
      version: version,
      name: name
    });

    return this._csrPEM;
  }

  
  /**
   * 
   */
  get ecKey () {

    this.logger.trace('ZitiContext.get ecKey() entered');

    if (isNull(this._ecKey)) {
      this._ecKey = this.generateECKey({});      
    }

    this.logger.trace('ZitiContext.get ecKey() completed');

    return this._ecKey;
  }
  
  /**
   * 
   */
  get privateKeyPEM () {

    if (isNull(this._ecKey)) {
      this._ecKey = this.generateECKey({});
    }
    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = this.getPrivateKeyPEM(this._ecKey)
    }

    return this._privateKeyPEM;
  }

  /**
   * 
   */
  get publicKeyPEM () {

    if (isNull(this._ecKey)) {
      this._ecKey = this.generateECKey({});
    }
    if (isNull(this._publicKeyPEM)) {
      this._publicKeyPEM = this.getPrivateKeyPEM(this._ecKey)
    }

    return this._publicKeyPEM;
  }


  /**
   * 
   */
  async getFreshAPISession() {
  
    this.logger.trace('ZitiContext.getFreshAPISession() entered');

    // Get an API session with Controller
    let res = await this._zitiBrowzerEdgeClient.authenticate({

      method: 'password',

      auth: { 

        username: this.updbUser,
        password: this.updbPswd,

        configTypes: [
          'ziti-tunneler-client.v1',
          'intercept.v1'
        ],

        envInfo: {

          // e.g.:  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36'
          arch: (typeof _ziti_realFetch !== 'undefined') ? window.navigator.userAgent : 'n/a',

          // e.g.:  'macOS', 'Linux', 'Windows'
          os: (typeof _ziti_realFetch !== 'undefined') ? navigator.userAgentData.platform : 'n/a'
        },
          
        sdkInfo: {
          type: this.sdkType,
          version: this.sdkVersion,
          branch: this.sdkBranch,
          revision: this.sdkRevision,
        },   
            
      }
    }).catch((error) => {
      throw error;
    });

    this.logger.trace('ZitiContext.getFreshAPISession(): response:', res);

    if (!isUndefined(res.error)) {
      this.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    this._apiSession = res.data;
    if (isUndefined( this._apiSession )) {
      throw new Error('response contains no data');
    }

    if (isUndefined( this._apiSession.token )) {
      throw new Error('response contains no token');
    }

    // Set the token header on behalf of all subsequent Controller API calls
    this._zitiBrowzerEdgeClient.setApiKey(this._apiSession.token, 'zt-session', false);

    this.logger.trace('ZitiContext.getFreshAPISession() exiting; token is: ', this._apiSession.token);

    return this._apiSession.token ;
  }


  /**
   * 
   */
  async ensureAPISession() {
  
    if (isUndefined( this._apiSession ) || isUndefined( this._apiSession.token )) {

      await this.getFreshAPISession().catch((error) => {
        throw error;
      });
                
    }
  
  }
  

  /**
   * 
   */
   async enroll() {
  
    await this._zitiEnroller.enroll();
  
  }

  
}

// Export class
export default ZitiContext

