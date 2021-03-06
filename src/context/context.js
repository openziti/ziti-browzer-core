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

import { PassThrough } from '../http/readable-stream/_stream_passthrough';
import Cookies from 'js-cookie';

import { flatOptions } from '../utils/flat-options'
import { defaultOptions } from './options'
import { ZitiEnroller } from '../enroll/enroller';
import { ZitiConnection } from '../channel/connection'
import { ZitiEdgeProtocol } from '../channel/protocol';
import { ZitiChannel } from '../channel/channel'
import throwIf from '../utils/throwif';
import { ZITI_CONSTANTS } from '../constants';
import { ZitiHttpRequest } from '../http/request';
import { HttpResponse } from '../http/response';
import { ZitiFormData } from '../http/form-data';
import { BrowserStdout } from '../http/browser-stdout';
import { http } from '../http/http';
import { ZitiWebSocketWrapperCtor } from '../http/ziti-websocket-wrapper-ctor';



import { LibCrypto, EVP_PKEY_EC, EVP_PKEY_RSA } from '@openziti/libcrypto-js'
import { ZitiBrowzerEdgeClient } from '@openziti/ziti-browzer-edge-client'
import {Mutex, withTimeout} from 'async-mutex';
import { isUndefined, isEqual, isNull, result, find, filter, has, minBy } from 'lodash-es';

 
// const EXPIRE_WINDOW = 28.0 // TEMP, for debugging
const EXPIRE_WINDOW = 2.0


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

    this._keyType = _options.keyType;

    this.logger = _options.logger;
    this.controllerApi = _options.controllerApi;

    this.updbUser = _options.updbUser;
    this.updbPswd = _options.updbPswd;
    this.token_type = _options.token_type;
    this.access_token = _options.access_token;

    this.sdkType = _options.sdkType;
    this.sdkVersion = _options.sdkVersion;
    this.sdkBranch = _options.sdkBranch;
    this.sdkRevision = _options.sdkRevision;

    this.apiSessionHeartbeatTimeMin  = _options.apiSessionHeartbeatTimeMin;
    this.apiSessionHeartbeatTimeMax = _options.apiSessionHeartbeatTimeMax;

    this.httpAgentTargetService = _options.httpAgentTargetService;

    this._libCrypto = new LibCrypto();
    this._libCryptoInitialized = false;

    this._network_sessions = new Map();
    this._services = new Map();
    this._channels = new Map();
    this._channelsById = new Map();
    
    /**
     * We start the channel id's at 10 so that they will be well above any 'fd'
     * used by traditional WebAssembly (i.e. stdin, stdout, stderr). In the WebAssembly
     * we have logic that watches for read/write operations to 'fd' values, and
     * any that target a 'fd' above 10 will route the i/o to the appropriate ZitiChannel.
     */
    this._channelSeq = 10;
    
    this._connSeq = 0;

    this._ensureAPISessionMutex = withTimeout(new Mutex(), 3 * 1000);
    this._getNetworkSessionByServiceIdMutex = withTimeout(new Mutex(), 3 * 1000);
    this._getServiceNameByHostNameAndPortMutex = withTimeout(new Mutex(), 3 * 1000);
    this._isCertExpiredMutex = withTimeout(new Mutex(), 3 * 1000);

    this._connectMutexWithTimeout = withTimeout(new Mutex(), 30 * 1000);

    this._pkey = null;
    this._privateKeyPEM = null;
    this._publicKeyPEM = null;
    this._casPEM = null;
    this._certPEM = null;
    this._apiSession = null;

    this._timeout = ZITI_CONSTANTS.ZITI_DEFAULT_TIMEOUT;

  }

  get libCrypto () {
    return this._libCrypto;
  }

  get timeout() {
    return this._timeout;
  }

  setKeyTypeEC() {
    this._keyType = EVP_PKEY_EC;
  }
  setKeyTypeRSA() {
    this._keyType = EVP_PKEY_RSA;
  }


  /**
   * 
   */
  async initialize(options) {

    if (this._initialized) throw Error("Already initialized; Cannot call .initialize() twice on instance.");

    this._zitiBrowzerEdgeClient = this.createZitiBrowzerEdgeClient ({
      logger: this.logger,
      controllerApi: this.controllerApi,
      domain: this.controllerApi,
      token_type: this.token_type,
      access_token: this.access_token,
    });

    if (options.loadWASM) {

      this.logger.trace(`libCrypto.initialize starting`);

      await this._libCrypto.initialize();

      this.logger.trace(`libCrypto.initialize completed; WASM is now available`);

    } else {

      this.logger.trace(`libCrypto.initialize bypassed (options.loadWASM is false)`);

    }

    this._initialized = true;    

    this._zitiEnroller = new ZitiEnroller ({
      logger: this.logger,
      zitiContext: this,
    });

  }


  /**
   * 
   */
   async reInitialize(options) {

    if (!this._initialized) throw Error("No previous initialization; Cannot call .reInitialize() yet.");

    this.logger.trace(`ZitiContext doing a reInitialize now`);

    this._zitiBrowzerEdgeClient = this.createZitiBrowzerEdgeClient ({
      logger: this.logger,
      controllerApi: this.controllerApi,
      domain: this.controllerApi,
      token_type: this.token_type,
      access_token: this.access_token,
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
   generateRSAKey() {

    this.logger.trace('ZitiContext.generateRSAKey() entered');

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._pkey = this._libCrypto.generateKey({});

    this.logger.trace('ZitiContext.generateRSAKey() exiting');

    return this._pkey;
  }

  /**
   * 
   */
  generateECKey() {

    this.logger.trace('ZitiContext.generateECKey() entered');

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._pkey = this._libCrypto.generateECKey({});

    this.logger.trace('ZitiContext.generateECKey() exiting');

    return this._pkey;
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
    name = "C=US, ST=NC, L=Charlotte, O=NetFoundry, OU=ADV-DEV, CN=ziti-browzer-core",
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
   get rsaKey () {

    if (isNull(this._pkey)) {
      this.logger.trace('ZitiContext.get rsaKey() needs to genetrate a new key');
      this._pkey = this.generateRSAKey({});      
    }

    return this._pkey;
  }

  /**
   * 
   */
  get ecKey () {

    if (isNull(this._pkey)) {
      this.logger.trace('ZitiContext.get ecKey() needs to genetrate a new key');
      this._pkey = this.generateECKey({});      
    }

    return this._pkey;
  }

  /**
   * 
   */
  get pKey () {

    if (isNull(this._pkey)) {

      switch(this._keyType) {

        case EVP_PKEY_RSA:
          {
            this._pkey = this.rsaKey;
          }
          break;
  
        case EVP_PKEY_EC:
          {
            this._pkey = this.ecKey;
          }
          break;
  
        default:
          throw Error("invalid _keyType");
      }
  
    }

    return this._pkey;
  }
  
  /**
   * 
   */
  get privateKeyPEM () {

    switch(this._keyType) {

      case EVP_PKEY_RSA:
        {
          if (isNull(this._pkey)) {
            this._pkey = this.generateRSAKey({});
          }
          if (isNull(this._privateKeyPEM)) {
            this._privateKeyPEM = this.getPrivateKeyPEM(this._pkey)
          }
        }
        break;

      case EVP_PKEY_EC:
        {
          if (isNull(this._pkey)) {
            this._pkey = this.generateECKey({});
          }
          if (isNull(this._privateKeyPEM)) {
            this._privateKeyPEM = this.getPrivateKeyPEM(this._pkey)
          }      
        }
        break;

      default:
        throw Error("invalid _keyType");
    }

    return this._privateKeyPEM;
  }

  /**
   * 
   */
  get publicKeyPEM () {

    switch(this._keyType) {

      case EVP_PKEY_RSA:
        {
          if (isNull(this._pkey)) {
            this._pkey = this.generateRSAKey({});
          }
          if (isNull(this._publicKeyPEM)) {
            this._publicKeyPEM = this.getPublicKeyPEM(this._pkey);
          }      
        }
        break;

      case EVP_PKEY_EC:
        {
          if (isNull(this._pkey)) {
            this._pkey = this.generateECKey({});
          }
          if (isNull(this._publicKeyPEM)) {
            this._publicKeyPEM = this.getPublicKeyPEM(this._pkey);
          }      
        }
        break;

      default:
        throw Error("invalid _keyType");
    }

    return this._publicKeyPEM;
  }


  /**
   * 
   * @returns 
   */
  async ssl_CTX_new() {

    this.logger.trace('ZitiContext.ssl_CTX_new() entered');

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    let sslContext = this._libCrypto.ssl_CTX_new();

    await this.ssl_CTX_add_certificate(sslContext);
    this.ssl_CTX_add_private_key(sslContext);
    this.ssl_CTX_verify_certificate_and_key(sslContext);

    this.logger.trace('ZitiContext.ssl_CTX_new() exiting');

    return sslContext;
  }

  /**
   * 
   * @returns 
   */
  ssl_CTX_add_private_key(sslContext) {

    this.logger.trace('ZitiContext.ssl_CTX_add_private_key() entered');

    sslContext = this._libCrypto.ssl_CTX_add_private_key(sslContext, this.pKey);

    if (isNull(sslContext)) throw Error("SSL Context failure.");

    this.logger.trace('ZitiContext.ssl_CTX_add_private_key() exiting');

    return sslContext;
  }

  /**
   * 
   * @returns 
   */
  async ssl_CTX_add_certificate(sslContext) {

    this.logger.trace('ZitiContext.ssl_CTX_add_certificate() entered');

    // Add client cert
    sslContext = this._libCrypto.ssl_CTX_add_certificate(sslContext, await this.getCertPEM());
    if (isNull(sslContext)) throw Error("SSL Context failure.");

    // Add CAs
    sslContext = this._libCrypto.ssl_CTX_add1_to_CA_list(sslContext, await this.getCasPEM());
    if (isNull(sslContext)) throw Error("SSL Context failure.");

    this.logger.trace('ZitiContext.ssl_CTX_add_certificate() exiting');

    return sslContext;
  }

  /**
   * 
   * @returns 
   */
  ssl_CTX_verify_certificate_and_key(sslContext) {

    this.logger.trace('ZitiContext.ssl_CTX_verify_certificate_and_key() entered');

    sslContext = this._libCrypto.ssl_CTX_verify_certificate_and_key(sslContext);

    if (isNull(sslContext)) throw Error("SSL Context failure.");

    this.logger.trace('ZitiContext.ssl_CTX_add_private_key() exiting');

    return sslContext;
  }

  /**
   * 
   */
  bio_new_ssl_connect(sslContext) {

    this.logger.trace('ZitiContext.bio_new_ssl_connect() entered');

    let bio = this._libCrypto.bio_new_ssl_connect(sslContext);

    if (isNull(bio)) throw Error("bio_new_ssl_connect create failure.");

    this.logger.trace('ZitiContext.bio_new_ssl_connect() exiting');

    return bio;
  }

  /**
   * 
   */
   bio_get_ssl(bio) {

    this.logger.trace('ZitiContext.bio_get_ssl() entered');

    let ssl = this._libCrypto.bio_get_ssl(bio);

    if (isNull(ssl)) throw Error("bio_get_ssl failure.");

    this.logger.trace('ZitiContext.bio_get_ssl() exiting');

    return ssl;
  }

  /**
   * 
   */
  bio_do_connect() {

    this.logger.trace('ZitiContext.bio_do_connect() entered');

    if (!this._sslContext) throw Error("No SSL Context exists; Must call .ssl_CTX_new() on instance.");
    if (!this._SSL_BIO) throw Error("No SSL_BIO exists; Must call .bio_new_ssl_connect() on instance.");

    let result = this._libCrypto.bio_do_connect(this._SSL_BIO);

    this.logger.trace('ZitiContext.bio_do_connect() exiting');

    return result;
  }

  /**
   * 
   */
   bio_set_conn_hostname(hostname) {

    this.logger.trace('ZitiContext.bio_set_conn_hostname() entered');

    if (!this._sslContext) throw Error("No SSL Context exists; Must call .ssl_CTX_new() on instance.");
    if (!this._SSL_BIO) throw Error("No SSL_BIO exists; Must call .bio_new_ssl_connect() on instance.");

    let result = this._libCrypto.bio_set_conn_hostname(this._SSL_BIO, hostname);

    this.logger.trace('ZitiContext.bio_set_conn_hostname() exiting');

    return result;
  }

  /**
   * 
   */
  ssl_do_handshake(ssl) {

    this.logger.trace('ZitiContext.ssl_do_handshake() entered');

    let result = this._libCrypto.ssl_do_handshake(ssl);

    this.logger.trace('ZitiContext.ssl_do_handshake() exiting, result=', result);

    return result;
  }
  
  /**
   * 
   * @returns 
   */
  ssl_new(sslContext) {

    this.logger.trace('ZitiContext.ssl_new() entered');

    let ssl = this._libCrypto.ssl_new(sslContext);

    if (isNull(ssl)) throw Error("SSL create failure.");

    this.logger.trace('ZitiContext.ssl_new() exiting');

    return ssl;
  }

  /**
   * 
   * @returns 
   */
  ssl_set_fd(ssl, fd) {

    this.logger.trace('ZitiContext.ssl_set_fd() entered');

    let result = this._libCrypto.ssl_set_fd(ssl, fd);

    if (result !== 1) throw Error("ssl_set_fd failure.");

    this.logger.trace('ZitiContext.ssl_set_fd() exiting');

    return result;
  }

  /**
   * 
   * @returns 
   */
  ssl_connect(ssl) {

    this.logger.trace('ZitiContext.ssl_connect() entered');

    let result = this._libCrypto.ssl_connect(ssl);

    this.logger.trace('ZitiContext.ssl_connect() exiting');

    return result;
  }

  /**
   * 
   */
   ssl_get_verify_result(ssl) {

    this.logger.trace('ZitiContext.ssl_get_verify_result() entered');

    let result = this._libCrypto.ssl_get_verify_result(ssl);

    this.logger.trace('ZitiContext.ssl_get_verify_result() exiting with: ', result);

    return result;

  }

  /**
   * 
   */
   tls_write(ssl, wireData) {

    this.logger.trace('ZitiContext.tls_write() entered');

    let result = this._libCrypto.tls_write(ssl, wireData);

    this.logger.trace('ZitiContext.tls_write() exiting with: ', result);

    return result;
  }
  
  /**
   * 
   */
  tls_read(ssl) {

    this.logger.trace('ZitiContext.tls_read() entered');

    let result = this._libCrypto.tls_read(ssl);

    this.logger.trace('ZitiContext.tls_read() exiting with: ', result);

    return result;
  }


  /**
   * 
   */
  async getFreshAPISession() {
  
    this.logger.trace('ZitiContext.getFreshAPISession() entered');

    // Use 'ext-jwt' style authentication, but allow for 'password' style (mostly for testing)
    let method = (isNull(this.access_token)) ? 'password' : 'ext-jwt';
    this.logger.trace('ZitiContext.getFreshAPISession(): method:', method);

    // Get an API session with Controller
    let res = await this._zitiBrowzerEdgeClient.authenticate({

      method: method,

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
          os: (typeof _ziti_realFetch !== 'undefined') ? (typeof navigator.userAgentData !== 'undefined' ? navigator.userAgentData.platform : 'n/a') : 'n/a'
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
      return null;
    }

    this._apiSession = res.data;
    if (isUndefined( this._apiSession )) {
      this.logger.error('response contains no data');
      return null;
    }

    if (isUndefined( this._apiSession.token )) {
      this.logger.error('response contains no token');
      return null;
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
  
    let token;

    await this._ensureAPISessionMutex.runExclusive(async () => {
      if (isNull( this._apiSession ) || isUndefined( this._apiSession.token )) {
        token = await this.getFreshAPISession().catch((error) => {
          token = null;
        });
      } else {
        token = this._apiSession.token;
      }
    });
  
    return token;
  }
  

  /**
   * 
   */
  async enroll() {
  
    if (isNull(this._certPEM)) {

      // Don't proceed until we have successfully logged in to Controller and have established an API session
      let token = await this.ensureAPISession();

      if (isUndefined(token) || isNull(token)) {
        this.logger.trace('ZitiContext.enroll(): ensureAPISession returned null');
        return false;
      }

      // Acquire the session cert
      let result = await this._zitiEnroller.enroll();

      if (!result) {
        this.logger.trace('ZitiContext.enroll(): enroll failed');
        return false;
      }

      this._casPEM = this._zitiEnroller.casPEM;
      this._certPEM = this._zitiEnroller.certPEM;
      this._certExpiryTime = this._zitiEnroller.certPEMExpiryTime;

      return true;
    }

  }

  /**
   * 
   */
   async getCasPEM () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = this.getPrivateKeyPEM(this._pkey)
    }
    if (isNull(this._certPEM)) {
      await this.enroll()
    }

    return this._casPEM;
  }

  /**
   * 
   */
  async getCertPEM () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = this.getPrivateKeyPEM(this._pkey)
    }
    if (isNull(this._certPEM)) {
      await this.enroll()
    }

    return this._certPEM;
  }

  /**
   * 
   */
  async getCertPEMExpiryTime () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = this.getPrivateKeyPEM(this._pkey)
    }
    if (isNull(this._certPEM)) {
      await this.enroll()
    }

    return this._certExpiryTime;
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
    
    if (isUndefined( this._services ) ) {
      throw new Error('response contains no data');
    }
    if ( this._services.length === 0) {
      throw new Error('list of services is empty!');
    }

    // this.logger.trace('List of available Services acquired: [%o]', this._services);
    
  }


  /**
   * 
   */
  async listControllerVersion() {
     
    let res = await this._zitiBrowzerEdgeClient.listVersion({ 
    }).catch((error) => {
      throw error;
    });

    this.logger.trace('ZitiContext.fetchControllerVersion(): response:', res);

    if (!isUndefined(res.error)) {
      this.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    this._controllerVersion = res.data;
    
    if (isUndefined( this._controllerVersion ) ) {
      throw new Error('response contains no data');
    }

    this.logger.info('Controller Version acquired: [%o]', this._controllerVersion);      
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
   
    await this._getNetworkSessionByServiceIdMutex.runExclusive(async () => {

      // if we do NOT have a NetworkSession for this serviceId, then create it
      if (!this._network_sessions.has(serviceID)) {

        let network_session = await this.createNetworkSession(serviceID)
        .catch((error) => {
          this.logger.error(error);
          throw error;
        });

        this.logger.debug('getNetworkSessionByServiceId() Created new network_session [%o] ', network_session);
  
        this._network_sessions.set(serviceID, network_session);
      }
    
    });

    let netSess = this._network_sessions.get(serviceID);

    this.logger.debug('getNetworkSessionByServiceId() returning network_session [%o] ', netSess);

    return netSess;
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
  

  /**
   * Allocate a new Connection.
   *
   * @param {*} data
   * @return {ZitiConnection}
   */
  newConnection(data) {

    let conn = new ZitiConnection({ 
      zitiContext: this,
      data: data
    });

    this.logger.trace('newConnection: conn[%d] data[%o]', conn.id, conn.data);

    return conn;
  };


  /**
   * Dial the `service`.
   *
   * @param {ZitiConnection} conn
   * @param {String} service
   */
  async dial( conn, service ) {

    throwIf(isUndefined(conn), 'connection not specified');
    throwIf(isUndefined(service), 'service not specified');
    throwIf(!isEqual(this, conn.zitiContext), 'connection has different context');

    this.logger.debug('dial: conn[%d] service[%s]', conn.id, service);

    if (isEqual( this.services.size, 0 )) {
      await this.fetchServices();
    }

    let service_id = this.getServiceIdByName(service);
    
    conn.encrypted = this.getServiceEncryptionRequiredByName(service);

    let network_session = await this.getNetworkSessionByServiceId(service_id);

    await this.connect(conn, network_session);

    this.logger.debug('dial: conn[%d] service[%s] encryptionRequired[%o] is now complete', conn.id, service, conn.encrypted);

  };


 /**
  * Connect specified ZitiConnection to the nearest Edge Router.
  * 
  * @param {Array} edgeRouters
  */
  async _getPendingChannelConnects(conn, edgeRouters) {

    return new Promise( async (resolve) => {

      this.logger.trace('_getPendingChannelConnects entered for edgeRouters [%o]', edgeRouters);

      let pendingChannelConnects = new Array();

      let self = this;
      
      // Get a channel connection to each of the Edge Routers that have a WS binding, initiating a connection if channel is not yet connected
      edgeRouters.forEach(async function(edgeRouter, idx, array) {
        self.logger.trace('calling getChannelByEdgeRouter for ER [%o]', edgeRouter);  
        let ch = await self.getChannelByEdgeRouter(conn, edgeRouter).catch((err) => {
          self.logger.error( err );  
          throw new Error( err );
        });
        self.logger.debug('initiating Hello to [%s] for session[%s]', edgeRouter.urls.ws, conn.networkSessionToken);  
        pendingChannelConnects.push( 
          ch.hello() 
        );

        if (idx === array.length - 1) {
          resolve(pendingChannelConnects);  // Return to caller only after we have processed all edge routers
        }
      });
    });
  }


 /**
  * Remain in lazy-sleepy loop until specified channel is connected.
  * 
  * @param {*} channel 
  */
  awaitChannelConnectComplete(ch) {
    return new Promise((resolve) => {
      (function waitForChannelConnectComplete() {
        if (isEqual( ch.state, ZitiEdgeProtocol.conn_state.Initial ) || isEqual( ch.state, ZitiEdgeProtocol.conn_state.Connecting )) {
          ch.zitiContext.logger.trace('awaitChannelConnectComplete() ch[%d] still not yet connected', ch.id);
          setTimeout(waitForChannelConnectComplete, 100);  
        } else {
          ch.zitiContext.logger.trace('ch[%d] is connected', ch.id);
          return resolve();
        }
      })();
    });
  }
  
  async getChannelByEdgeRouter(conn, edgeRouter) {

    throwIf(isUndefined(conn), 'connection not specified');
    throwIf(!isEqual(this, conn.zitiContext), 'connection has different context');
    throwIf(isUndefined(conn.networkSessionToken), 'connection.networkSessionToken not specified');
    throwIf(isUndefined(edgeRouter), 'edgeRouter not specified');

  
    this.logger.trace('getChannelByEdgeRouter entered for conn[%d] edgeRouter[%s]', conn, edgeRouter.hostname);

    let key = edgeRouter.hostname + '-' + conn.networkSessionToken;

    this.logger.trace('getChannelByEdgeRouter key[%s]', key);

    let ch = this._channels.get( key );

    this.logger.trace('getChannelByEdgeRouter ch[%o]', ch);

    if (!isUndefined(ch)) {

      this.logger.debug('ch[%d] state[%d] found for edgeRouter[%s]', ch.id, ch.state, edgeRouter.hostname);

      await this.awaitChannelConnectComplete(ch);

      this.logger.debug('ch[%d] state[%d] for edgeRouter[%s] is connect-complete', ch.id, ch.state, edgeRouter.hostname);

      if (!isEqual( ch.state, ZitiEdgeProtocol.conn_state.Connected )) {
        this.logger.error('should not be here: ch[%d] has state[%d]', ch.id, ch.state);
      }

      return (ch);
    }
  
    // Create a Channel for this Edge Router
    ch = new ZitiChannel({ 
      zitiContext: this,
      edgeRouter: edgeRouter,
      session_token: this._apiSession.token,
      network_session_token: conn.networkSessionToken
    });

    ch.state = ZitiEdgeProtocol.conn_state.Connecting;

    this.logger.debug('Created ch[%o] ', ch);
    this._channels.set(key, ch);
    this._channelsById.set(ch.id, ch);
    
    this.logger.trace('getChannelByEdgeRouter returning ch[%o]', ch);

    return ch;
  }
 
 

 /**
  * Connect specified ZitiConnection to the nearest Edge Router.
  * 
  * @param {ZitiConnection} conn
  * @param {*} networkSession
  */
  async connect(conn, networkSession) {
   
    this.logger.debug('connect() entered for conn[%o] networkSession[%o]', conn.id, networkSession);  
  
    // If we were not given a networkSession, it most likely means something (an API token, Cert, etc) expired,
    // so we need to purge them and re-acquire
    // if (isNull(networkSession) || isUndefined( networkSession )) {
  
    //   this.logger.debug('ctx.connect invoked with undefined networkSession');  
    
    //   await this._awaitIdentityLoadComplete().catch((err) => {
    //     self.logger.error( err );  
    //     throw new Error( err );
    //   });
    // }
  
    conn.networkSessionToken = networkSession.token;
  
    // Get list of all Edge Router URLs where the Edge Router has a WS binding
    let edgeRouters = filter(networkSession.edgeRouters, function(o) { return has(o, 'urls.ws'); });
    this.logger.trace('edgeRouters [%o]', edgeRouters);  

    // Something is wrong if we have no ws-enabled edge routers
    if (isEqual(edgeRouters.length, 0)) {
      throw new Error('No Edge Routers with ws: binding were found');
    }
  
    //
    this.logger.debug('trying to acquire _connectMutex for conn[%o]', conn.id);
  
    await this._connectMutexWithTimeout.runExclusive(async () => {
  
      this.logger.debug('now own _connectMutex for conn[%o]', conn.id);
  
      let pendingChannelConnects = await this._getPendingChannelConnects(conn, edgeRouters);
      this.logger.trace('pendingChannelConnects [%o]', pendingChannelConnects);  
  
      let channelConnects = await Promise.all( pendingChannelConnects );
      this.logger.trace('channelConnects [%o]', channelConnects);  
  
      // Select channel with nearest Edge Router. Heuristic: select one with earliest Hello-handshake completion timestamp
      let channelConnectWithNearestEdgeRouter = minBy(channelConnects, function(channelConnect) { 
        return channelConnect.channel.helloCompletedTimestamp;
      });
      
      let channelWithNearestEdgeRouter = channelConnectWithNearestEdgeRouter.channel;
      this.logger.debug('Channel [%d] has nearest Edge Router for conn[%o]', channelWithNearestEdgeRouter.id, conn.id);
      channelWithNearestEdgeRouter._connections._saveConnection(conn);
      conn.channel = channelWithNearestEdgeRouter;
  
      // Initiate connection with Edge Router (creates Fabric session)
      await channelWithNearestEdgeRouter.connect(conn);
  
      if (conn.state == ZitiEdgeProtocol.conn_state.Connected) {
        if (conn.encrypted) {  // if connected to a service that has 'encryptionRequired'
          // Do not proceed until crypto handshake has completed
          await channelWithNearestEdgeRouter.awaitConnectionCryptoEstablishComplete(conn);
        }
      }
      this.logger.debug('releasing _connectMutex for conn[%o]', conn.id);
    })
    .catch(( err ) => {
      this.logger.error(err);
      throw new Error(err);
    });  
  }


 /**
  * Determine if the given URL should be routed over Ziti.
  * 
  * @param {*} url
  */
  async shouldRouteOverZiti(url) {
   
    this.logger.debug('shouldRouteOverZiti() entered for url[%o]', url);  

    let parsedURL = new URL(url);
 
    let hostname = parsedURL.hostname;
    let port = parsedURL.port;
  
    if (port === '') {
      if ((parsedURL.protocol === 'https:') || (parsedURL.protocol === 'wss:')) {
        port = 443;
      } else {
        port = 80;
      }
    }
    
    let serviceName = await this.getServiceNameByHostNameAndPort(hostname, port).catch(( error ) => {
      throw new Error( error );
    });
  
    return serviceName;
   
  }


  /**
   * 
   * @param {*} hostname 
   * @param {*} port 
   * @returns 
   */
  async getServiceNameByHostNameAndPort(hostname, port) {

    if (typeof port === 'string') {
      port = parseInt(port, 10);
    }

    await this._getServiceNameByHostNameAndPortMutex.runExclusive(async () => {
      if (isEqual( this.services.size, 0 )) {
        await this.fetchServices().catch((error) => {
          throw new Error(error);
        });
      }
    });

    let self = this;

    let serviceName = result(find(this._services, function(obj) {

      if (self._getMatchConfigTunnelerClientV1( obj.config['ziti-tunneler-client.v1'], hostname, port )) {
        return true;
      }

      return self._getMatchConfigInterceptV1( obj.config['intercept.v1'], hostname, port );

    }), 'name');

    return serviceName;
  }


  /**
   "config": {
     "ziti-tunneler-client.v1": {
         "ziti-tunneler-client.v1": {
           "hostname": "example.com",
          "port": 443
        }
      }
    }
  */
  _getMatchConfigTunnelerClientV1 = function(config, hostname, port) {
    if (isUndefined(config)) {
      return false;
    }
    if (config.hostname !== hostname) {
      return false;
    }
    if (config.port !== port) {
      return false;
    }
    return true;
  }


  /**
    "config": {
      "intercept.v1": {
        "addresses": ["example.com"],
        "portRanges": [{
          "high": 443,
          "low": 443
        }],
        "protocols": ["tcp"]
      }
    }
  */
  _getMatchConfigInterceptV1 = function(config, hostname, port) {
    if (isUndefined(config)) {
      return false;
    }
    let foundAddress = result(find(config.addresses, function(address) {
      if (address !== hostname) {
        return false;
      }
      return true;  
    }), 'name', 'default');

    if (!foundAddress || foundAddress === 'default') {
      return false;
    }

    let foundPort = result(find(config.portRanges, function(portRange) {
      if ((port >= portRange.low) && (port <= portRange.high)) {
        return true;
      }
      return false;  
    }), 'name', 'default');

    if (!foundPort || foundPort === 'default') {
      return false;
    }

    return true;
  }


 /**
  * 
  */
  async isCertExpired() {
 
    await this._isCertExpiredMutex.runExclusive(async () => {

      let expired = false;

      let certExpiry = await this.getCertPEMExpiryTime();

      let now = Date.now();
      const diffTime = (certExpiry - now);
      const diffMins = (diffTime / (1000 * 60));

      this.logger.debug('mins before cert expiration [%o]', diffMins);

      if (diffMins < EXPIRE_WINDOW) { // if expired, or about to expire

        this.flushExpiredAPISessionData(); 

        expired = true;
      
      }

      return expired;

    });
  }

 /**
  *
  */
  flushExpiredAPISessionData() {
 
    this._casPEM = null;
    this._certPEM = null;
    this._apiSession = null;
  
   }
 
 

  /**
   * 
   */
  getNextConnectionId() {
    this._connSeq++;
    return this._connSeq;
  }

  /**
   * 
   */
  getNextChannelId() {
    this._channelSeq++;
    return this._channelSeq;
  }
 

  closeChannelByEdgeRouter( edgeRouter ) {
    this._channels.delete( edgeRouter );  
    this._channelsById.delete( edgeRouter.id );  
  }
  
  closeAllChannels() {
    this._channels = new Map();
    this._channelsById = new Map();
  }
 
  get zitiWebSocketWrapper() {
    return ZitiWebSocketWrapperCtor;
  }

 /**
  * Close specified ZitiConnection with Edge Router.
  * 
  * @param {ZitiConnection} conn
  */
  async close(conn) {
    let ch = conn.channel;
    await ch.close(conn);
    ch._connections._deleteConnection(conn);
  }
 
 

  /**
   * 
   * @param {*} options 
   * @returns Promise
   */
   async httpFetch (url, opts) {

    let self = this;

    return new Promise( async (resolve, reject) => {

      /**
       * ------------ Now Routing over Ziti -----------------
       */
      self.logger.debug('httpFetch starting for [%s]', url);

      // build HTTP request object
      let request = new ZitiHttpRequest(opts.serviceName, url, opts, this);
      let options = await request.getRequestOptions();
      // options.domProxyHit = domProxyHit;

      let req;

      if (options.method === 'GET') {
  
        req = http.get(options);
  
      } else {

        req = http.request(options);

        if (options.body) {
          if (options.body instanceof Promise) {
            let chunk = await options.body;
            req.write( chunk );
          }
          else if (options.body instanceof ZitiFormData) {
  
            let p = new Promise((resolve, reject) => {
  
              let stream = options.body.getStream();
  
              stream.on('error', err => {
                reject(new Error(`${err.message}`));
              });
  
              stream.on('end', () => {
                try {
                  resolve();
                } catch (err) {
                  reject(new Error(`${err.message}`));
                }
              });
  
              stream.pipe(new BrowserStdout({req: req}))
            });
  
            await p;
  
          }
          else {
            req.write( options.body );
          }
        }
  
        req.end();
  
      }

      req.on('error', err => {
        self.logger.error('error EVENT: err: %o', err);
        reject(new Error(`request to ${request.url} failed, reason: ${err.message}`));
      });
  
      req.on('response', async res => {

        let body = res.pipe(new PassThrough());
  
        const response_options = {
          url: url,
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          size: request.size,
          timeout: request.timeout,
          counter: request.counter
        };
        let response = new HttpResponse(body, response_options);
  
        for (const hdr in response_options.headers) {
          if (response_options.headers.hasOwnProperty(hdr)) {
            if (hdr === 'set-cookie') {
              let cookieArray = response_options.headers[hdr];
              let cookiePath;
              let expires;
              let httpOnly = false;
  
              //   let zitiCookies = await ls.getWithExpiry(zitiConstants.get().ZITI_COOKIES);
              //   if (isNull(zitiCookies)) {
              //     zitiCookies = {}
              //   }
  
              for (let i = 0; i < cookieArray.length; i++) {
  
                let cookie = cookieArray[i];
                let name = cookie.substring(0, cookie.indexOf("="));
                let value = cookie.substring(cookie.indexOf("=") + 1);
                let cookie_value = value.substring(0, value.indexOf(";"));
                if (cookie_value !== ''){
                  let parts = value.split(";");
                  for (let j = 0; j < parts.length; j++) {
                    let part = parts[j].trim();
                    if ( part.startsWith("Path") ) {
                      cookiePath = part.substring(part.indexOf("=") + 1);
                    }
                    else if ( part.startsWith("Expires") ) {
                      expires = new Date( part.substring(part.indexOf("=") + 1) );
                    }
                    else if ( part.startsWith("HttpOnly") ) {
                      httpOnly = true;
                    }
                  }
  
  
                  //       zitiCookies[name] = cookie_value;
  
                  //       await ls.setWithExpiry(zitiConstants.get().ZITI_COOKIES, zitiCookies, new Date(8640000000000000));
  
                  Cookies.set(name, cookie_value, { expires: expires, path:  cookiePath});
                }
              }
            }
          }
        }
        
        resolve(response);
      });
  
    });
  
  }

}

// Export class
export default ZitiContext

