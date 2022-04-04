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
// import edge_protocol from '../channel/protocol';

import { LibCrypto } from '@openziti/libcrypto-js'
import { ZitiBrowzerEdgeClient } from '@openziti/ziti-browzer-edge-client'
import {Mutex, withTimeout} from 'async-mutex';
import { isUndefined, isNull, result, find } from 'lodash-es';

 
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

    this.apiSessionHeartbeatTimeMin  = _options.apiSessionHeartbeatTimeMin;
    this.apiSessionHeartbeatTimeMax = _options.apiSessionHeartbeatTimeMax;

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

    setTimeout(this.apiSessionHeartbeat, this.getApiSessionHeartbeatTime(), this );

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


  /**
   *
   */
  async apiSessionHeartbeat(self) {

    self.logger.trace('ZitiContext.apiSessionHeartbeat() entered');

    let res = await self._zitiBrowzerEdgeClient.getCurrentAPISession({ }).catch((error) => {
      throw error;
    });

    self.logger.trace('ZitiContext.apiSessionHeartbeat(): response:', res);

    if (!isUndefined(res.error)) {
      self.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    self._apiSession = res.data;
    if (isUndefined( self._apiSession )) {
      throw new Error('response contains no data');
    }

    if (isUndefined( self._apiSession.token )) {
      throw new Error('response contains no token');
    }

    // Set the token header on behalf of all subsequent Controller API calls
    self._zitiBrowzerEdgeClient.setApiKey(self._apiSession.token, 'zt-session', false);

    self.logger.trace('ZitiContext.apiSessionHeartbeat() exiting; token is: ', self._apiSession.token);

    setTimeout(self.apiSessionHeartbeat, self.getApiSessionHeartbeatTime(), self );

  }


  /**
   * 
   */
  getApiSessionHeartbeatTime() {
    let time = this.getRandomInt(this.apiSessionHeartbeatTimeMin, this.apiSessionHeartbeatTimeMax);
    this.logger.debug('mins before next heartbeat: ', time);
    return (time * 1000 * 60);
  }

  /**
   * Returns a random integer between min (inclusive) and max (inclusive).
   */
  getRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  

  /**
   * 
   */
  async fetchServices() {
     
    await this.ensureAPISession();

    // Get list of active Services from Controller
    let res = await this._zitiBrowzerEdgeClient.listServices({ 
      limit: '100' //TODO add paging support
    }).catch((error) => {
      throw error;
    });

    // this.logger.trace('ZitiContext.fetchServices(): response:', res);

    if (!isUndefined(res.error)) {
      this.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    this._services = res.data;
    if (isUndefined( this._services )) {
      throw new Error('response contains no data');
    }

    // this.logger.trace('List of available Services acquired: [%o]', this._services);
    
  }

  get services () {
    return this._services;
  }


  /**
   * 
   */
  getServiceIdByName(name) {
    let service_id = result(find(this._services, function(obj) {
      return obj.name === name;
    }), 'id');
    this.logger.trace('service[%s] has id[%s]', name, service_id);
    return service_id;
  }
 

  /**
   * 
   */
  getServiceEncryptionRequiredByName (name) {
    let encryptionRequired = result(find(this._services, function(obj) {
      return obj.name === name;
    }), 'encryptionRequired');
    this.logger.trace('service[%s] has encryptionRequired[%o]', name, encryptionRequired);
    return encryptionRequired;
  }
 
 
  /**
   * 
   */
  async getNetworkSessionByServiceId(serviceID) {
   
    await this._mutex.runExclusive(async () => {

      // if we do NOT have a NetworkSession for this serviceId, create it
      if (!this._network_sessions.has(serviceID)) {

        let network_session = await this.createNetworkSession(serviceID)
        .catch((error) => {
          this.logger.error(error);
          throw error;
        });
  
        if (!isUndefined( network_session )) {
      
          this.logger.debug('Created new network_session [%o] ', network_session);
    
        }
  
        this._network_sessions.set(serviceID, network_session);
      }
    
    });

    return ( this._network_sessions.get(serviceID) );
  }


  /**
   * 
   */
  async createNetworkSession(id) {
 
    let res = await this._zitiBrowzerEdgeClient.createSession({
      session: { 
        serviceId: id,
        type: 'Dial'
      }
      //,
      // headers: { 
      //   'Content-Type': 'application/json'
      // }
    }).catch((error) => {
      this.logger.error(error);
      throw error;
    });

    this.logger.trace('ZitiContext.createSession(): response:', res);

    if (!isUndefined(res.error)) {
      this.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    let network_session = res.data;
    if (isUndefined( network_session )) {
      throw new Error('response contains no data');
    }

    return( network_session );  
  }
  
 
}

// Export class
export default ZitiContext

