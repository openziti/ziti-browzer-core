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

import { PassThrough } from '../http/readable-stream/_stream_passthrough';
import memoize from 'fast-memoize';
import Cookies from 'js-cookie';
import { Buffer } from 'buffer/';
import {
  calculatePKCECodeChallenge,
  generateRandomCodeVerifier,
  generateRandomState
} from 'oauth4webapi';


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
import { ZitiAgentPool } from '../http/ziti-agent-pool';
import { ZitiWASMFD } from './wasmFD';
import {
  splitPemChain
} from '../utils/pki';




import { LibCrypto, EVP_PKEY_EC, EVP_PKEY_RSA } from '@openziti/libcrypto-js'
import { ZitiBrowzerEdgeClient } from '@openziti/ziti-browzer-edge-client'
import {Mutex, withTimeout, Semaphore} from 'async-mutex';
import { isUndefined, isEqual, isNull, result, find, filter, has, minBy, forEach } from 'lodash-es';
import EventEmitter from 'events';
import {isIP} from 'is-ip';
import jwt_decode from 'jwt-decode';
import ElapsedTime from 'elapsed-time';

 
// const EXPIRE_WINDOW = 28.0 // TEMP, for debugging
const EXPIRE_WINDOW = 2.0


/**
 *    ZitiContext
 */
class ZitiContext extends EventEmitter {

  /**
   * 
   */
  constructor(options) {

    super();

    this._initialized = false;
    this._initializedInnerWASM = false;

    let _options = flatOptions(options, defaultOptions);

    this._keyType = _options.keyType;

    this.logger = _options.logger;
    this.controllerApi = _options.controllerApi;

    this.updbUser = _options.updbUser;
    this.updbPswd = _options.updbPswd;
    this.token_type = _options.token_type;
    this.id_token = _options.id_token;
    this.access_token = _options.access_token;

    this.sdkType = _options.sdkType;
    this.sdkVersion = _options.sdkVersion;
    this.sdkBranch = _options.sdkBranch;
    this.sdkRevision = _options.sdkRevision;

    this.apiSessionHeartbeatTimeMin  = _options.apiSessionHeartbeatTimeMin;
    this.apiSessionHeartbeatTimeMax = _options.apiSessionHeartbeatTimeMax;

    this.bootstrapperTargetService = _options.bootstrapperTargetService;

    this.bootstrapperHost = _options.bootstrapperHost;

    this.proxydomain = `https://${this.bootstrapperHost}${ZITI_CONSTANTS.ZITI_BOOTSTRAPPER_CONTROLLER_PROXY_PATH}`;

    this._libCrypto = new LibCrypto();
    this._libCryptoInitialized = false;

    this._network_sessions = new Map();
    this._services = new Map();
    this._channels = new Map();
    this._channelsById = new Map();
    this._wasmFDsById = new Map();
    
    /**
     * We start the channel id's at 10 so that they will be well above any 'fd'
     * used by traditional WebAssembly (i.e. stdin, stdout, stderr). In the WebAssembly
     * we have logic that watches for read/write operations to 'fd' values, and
     * any that target a 'fd' above 10 will route the i/o to the appropriate ZitiChannel|ZitiTLSSocket.
     */
    this._channelSeq = 10;
    this._wasmFDSeq  = 10;
    
    this._connSeq = 0;

    this._ensureAPISessionMutex = withTimeout(new Mutex(), 3 * 1000);
    this._getNetworkSessionByServiceIdMutex = withTimeout(new Mutex(), 3 * 1000);
    this._getServiceNameByHostNameAndPortMutex = withTimeout(new Mutex(), 3 * 1000);
    this._isCertExpiredMutex = withTimeout(new Mutex(), 3 * 1000);

    this._connectMutexWithTimeout = withTimeout(new Mutex(), 30 * 1000);

    this._tlsHandshakeLock = withTimeout(new Mutex(), 30 * 1000, new Error('timeout on _tlsHandshakeLock'));

    this._fetchSemaphoreHTTP  = new Semaphore( 8 );
    this._fetchSemaphoreHTTPS = new Semaphore( 8 );

    this._pkey = null;
    this._privateKeyPEM = null;
    this._publicKeyPEM = null;
    this._casPEM = null;
    this._certPEM = null;
    this._apiSession = null;

    this._timeout = ZITI_CONSTANTS.ZITI_DEFAULT_TIMEOUT;

    this._didInitialGetPendingChannelConnects = false;

    this._agentPool = new ZitiAgentPool({

      // maximum number of ZitiAgent's the pool should contain
      max: 25,

      // number of milliseconds a client must sit idle in the pool and not be checked out
      // before it is disconnected from the backend and discarded
      // default is 10000 (10 seconds) - setting to 0 to disables auto-disconnection of idle clients
      idleTimeoutMillis: 0,

      // number of milliseconds to wait before timing out when connecting a new ZitiAgent - 0 means no timeout
      connectionTimeoutMillis: (10 * 1000),

      // pass the pool our logger
      logger: this.logger,

    })

    this.controllerCapabilities = [];
    this.controllerCapabilitiesOIDCErrorEncountered = false;
    
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

    await this.listControllerVersion();
    await this.listExternalJwtSigners();

    if (options.loadWASM) {

      let _real_Date_now = Date.now;  // work around an Emscripten issue

      if (!options.jspi) {
        this.logger.trace(`libCrypto.initialize_NO_JSPI starting`);
        await this._libCrypto.initialize_NO_JSPI();
        this.logger.trace(`libCrypto.initialize_NO_JSPI completed; WASM is now available`);
      }
      else {
        this.logger.trace(`libCrypto.initialize_JSPI starting`);
        await this._libCrypto.initialize_JSPI();
        this.logger.trace(`libCrypto.initialize_JSPI completed; WASM is now available`);
      }

      Date.now = _real_Date_now;      // work around an Emscripten issue

    } else {

      this.logger.trace(`libCrypto.initialize() bypassed (options.loadWASM is false)`);

    }

    if (options.doAuthenticate) {

      this.targetService = options.target;
      this.targetServiceAppData = await this.getConnectAppDataByServiceName (this.targetService.service, this.targetService.scheme);
      this.targetServiceHost = await this.getConfigHostByServiceName (this.targetService.service);
      this.targetServiceHostAndPort = undefined;
      if (!isUndefined(this.targetServiceAppData)) {
        this.targetServiceHostAndPort = `${this.targetServiceAppData.dst_hostname}:${this.targetServiceAppData.dst_port}`;
      }
      this.bootstrapperHost = options.bootstrapperHost;

    }

    this._zitiEnroller = new ZitiEnroller ({
      logger: this.logger,
      zitiContext: this,
    });

    this._initialized = true;
  }

 /**
  * Remain in lazy-sleepy loop until context is initialized.
  * 
  * @param {*} ctx 
  */
  awaitInitializationComplete() {
    let self = this;
    return new Promise((resolve) => {
      (function waitForInitializationComplete() {
        if (!self._initialized) {
          setTimeout(waitForInitializationComplete, 10);  
        } else {
          return resolve();
        }
      })();
    });
  }

 /**
  * Remain in lazy-sleepy loop until we have the access token.
  * 
  * @param {*} ctx 
  */
 awaitAccessTokenPresent() {
  let self = this;
  return new Promise((resolve) => {
    (function waitForAccessTokenPresent() {
      let access_token;
      if (self.isControllerHA()) {
        access_token = self._apiSession.access_token;
      } else {
        access_token = self._apiSession.token;
      }
      if (!access_token) {
        setTimeout(waitForAccessTokenPresent, 10);  
      } else {
        return resolve();
      }
    })();
  });
}


  /**
   * 
   */
  getZitiAgentPool() {
    return this._agentPool;
  }


  /**
   * 
   */
  async getWASMInstance() {
  
    let WASMInstance = await this._libCrypto.getWASMInstance();
      
    return WASMInstance;
  
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
      id_token: this.id_token,
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
   async generateRSAKey() {

    this.logger.trace('ZitiContext.generateRSAKey() entered');

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._pkey = this._libCrypto.generateKey( await this.getWASMInstance() );

    this.logger.trace('ZitiContext.generateRSAKey() exiting');

    return this._pkey;
  }

  /**
   * 
   */
  async generateECKey() {

    this.logger.trace('ZitiContext.generateECKey() entered');

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    let wasmInstance = await this.getWASMInstance();

    this._pkey = this._libCrypto.generateECKey( wasmInstance );

    this.logger.trace(`ZitiContext.generateECKey() exiting, pkey[${this._pkey}]`);

    return this._pkey;
  }

  /**
   * 
   */
  async getPrivateKeyPEM(pkey) {

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._privateKeyPEM = this._libCrypto.getPrivateKeyPEM(await this.getWASMInstance(), pkey);

    return this._privateKeyPEM;
  }

  /**
   * 
   */
  async getPublicKeyPEM(pkey) {

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    this._publicKeyPEM = this._libCrypto.getPublicKeyPEM(await this.getWASMInstance(), pkey);

    return this._publicKeyPEM;
  }

  /**
   * 
   */
  createCertificateSigningRequest(wasmInstance, {
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

    this._csrPEM = this._libCrypto.createCertificateSigningRequest(
      wasmInstance,
      {
        key: key,
        curve: curve,
        compressed: compressed,
        version: version,
        name: name
      }
    );

    return this._csrPEM;
  }

  
  /**
   * 
   */
   async get_rsaKey () {

    if (isNull(this._pkey)) {
      this.logger.trace('ZitiContext.get rsaKey() needs to genetrate a new key');
      this._pkey = await this.generateRSAKey();      
    }

    return this._pkey;
  }

  /**
   * 
   */
  async get_ecKey() {

    if (isNull(this._pkey)) {
      this.logger.trace('ZitiContext.get ecKey() needs to generate a new key');
      this._pkey = await this.generateECKey();      
    }

    return this._pkey;
  }

  /**
   * 
   */
  async get_pKey () {

    if (isNull(this._pkey)) {

      switch(this._keyType) {

        case EVP_PKEY_RSA:
          {
            this._pkey = this.get_rsaKey();
          }
          break;
  
        case EVP_PKEY_EC:
          {
            this._pkey = await this.get_ecKey();
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
  async get_privateKeyPEM () {

    switch(this._keyType) {

      case EVP_PKEY_RSA:
        {
          if (isNull(this._pkey)) {
            this._pkey = await this.generateRSAKey();
          }
          if (isNull(this._privateKeyPEM)) {
            this._privateKeyPEM = await this.getPrivateKeyPEM(this._pkey)
          }
        }
        break;

      case EVP_PKEY_EC:
        {
          if (isNull(this._pkey)) {
            this._pkey = await this.generateECKey();
          }
          if (isNull(this._privateKeyPEM)) {
            this._privateKeyPEM = await this.getPrivateKeyPEM(this._pkey)
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
  async get_publicKeyPEM () {

    switch(this._keyType) {

      case EVP_PKEY_RSA:
        {
          if (isNull(this._pkey)) {
            this._pkey = await this.generateRSAKey();
          }
          if (isNull(this._publicKeyPEM)) {
            this._publicKeyPEM = await this.getPublicKeyPEM(this._pkey);
          }      
        }
        break;

      case EVP_PKEY_EC:
        {
          if (isNull(this._pkey)) {
            this._pkey = await this.generateECKey();
          }
          if (isNull(this._publicKeyPEM)) {
            this._publicKeyPEM = await this.getPublicKeyPEM(this._pkey);
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
  async ssl_CTX_new( wasmInstance ) {

    this.logger.trace('ZitiContext.ssl_CTX_new() entered');

    if (!this._initialized) throw Error("Not initialized; Must call .initialize() on instance.");

    let sslContext = this._libCrypto.ssl_CTX_new( wasmInstance );
    this.logger.trace('ZitiContext.ssl_CTX_new() _libCrypto.ssl_CTX_new() returned [%o]', sslContext);

    await this.ssl_CTX_add_certificate(wasmInstance, sslContext);
    await this.ssl_CTX_add_private_key(wasmInstance, sslContext);
    // this.ssl_CTX_verify_certificate_and_key(wasmInstance, sslContext);

    this.logger.trace('ZitiContext.ssl_CTX_new() exiting');

    return sslContext;
  }

  /**
   * 
   * @returns 
   */
  async ssl_CTX_add_private_key(wasmInstance, sslContext) {

    this.logger.trace('ZitiContext.ssl_CTX_add_private_key() entered');

    let pKey = await this.get_pKey();

    sslContext = this._libCrypto.ssl_CTX_add_private_key(wasmInstance, sslContext, pKey);

    if (isNull(sslContext)) throw Error("SSL Context failure.");

    this.logger.trace('ZitiContext.ssl_CTX_add_private_key() exiting');

    return sslContext;
  }

  /**
   * 
   * @returns 
   */
  async ssl_CTX_add_certificate(wasmInstance, sslContext) {

    this.logger.trace('ZitiContext.ssl_CTX_add_certificate() entered');

    // Add client cert
    sslContext = this._libCrypto.ssl_CTX_add_certificate(wasmInstance, sslContext, await this.getCertPEMLeaf());
    if (isNull(sslContext)) throw Error("SSL Context failure.");

    // Add remaining certs in the chain
    for (const intermediatePEM of await this.getCertPEMIntermediatesArray()) {
      sslContext = this._libCrypto.ssl_CTX_add_extra_chain_cert(wasmInstance, sslContext, intermediatePEM);
      if (isNull(sslContext)) throw Error("SSL Context failure.");
    }

    this.logger.trace('ZitiContext.ssl_CTX_add_certificate() exiting');

    return sslContext;
  }

  /**
   * 
   * @returns 
   */
  ssl_CTX_verify_certificate_and_key(wasmInstance, sslContext) {

    this.logger.trace('ZitiContext.ssl_CTX_verify_certificate_and_key() entered');

    sslContext = this._libCrypto.ssl_CTX_verify_certificate_and_key(wasmInstance, sslContext);

    if (isNull(sslContext)) throw Error("SSL Context failure.");

    this.logger.trace('ZitiContext.ssl_CTX_verify_certificate_and_key() exiting');

    return sslContext;
  }

  /**
   * 
   */
  bio_new_ssl_connect(wasmInstance, sslContext) {

    this.logger.trace('ZitiContext.bio_new_ssl_connect() entered, sslContext: ', sslContext);

    let bio = this._libCrypto.bio_new_ssl_connect(wasmInstance, sslContext);

    if (isNull(bio)) throw Error("bio_new_ssl_connect create failure.");

    this.logger.trace('ZitiContext.bio_new_ssl_connect() exiting, bio[%o]', bio);

    return bio;
  }

  /**
   * 
   */
   bio_get_ssl(wasmInstance, bio) {

    this.logger.trace('ZitiContext.bio_get_ssl() entered');

    let ssl = this._libCrypto.bio_get_ssl(wasmInstance, bio);

    if (isNull(ssl)) throw Error("bio_get_ssl failure.");

    this.logger.trace('ZitiContext.bio_get_ssl() exiting, ssl[%o]', ssl);

    return ssl;
  }

  /**
   * 
   */
   async ssl_do_handshake(useLock, fd, wasmInstance, ssl) {

    if (useLock) {
      await this.acquireTLSHandshakeLock(fd);
    }

    this.logger.trace('ZitiContext.ssl_do_handshake() entered');

    let result = await this._libCrypto.ssl_do_handshake(wasmInstance, ssl);

    this.logger.trace(`ZitiContext.ssl_do_handshake() exiting, result[${result}]`);

    return result;
  }

  ssl_is_init_finished(wasmInstance, ssl) {

    return this._libCrypto.ssl_is_init_finished(wasmInstance, ssl);

  }
  
  /**
   * 
   * @returns 
   */
  ssl_set_fd(wasmInstance, ssl, fd) {

    this.logger.trace(`ZitiContext.ssl_set_fd() entered SSL[${ssl}] fd[${fd}]`);

    let result = this._libCrypto.ssl_set_fd(wasmInstance, ssl, fd);

    if (result !== 1) throw Error("ssl_set_fd failure.");

    this.logger.trace('ZitiContext.ssl_set_fd() exiting');

    return result;
  }

  /**
   * 
   */
  async acquireTLSHandshakeLock(fd) {
    this.logger.trace(`ZitiContext.acquireTLSHandshakeLock() [${fd}] trying to acquire _tlsHandshakeLock`);
    this._tlsHandshakeLockRelease = await this._tlsHandshakeLock.acquire();
    this._tlsHandshakeLockFD = fd;
    this.logger.trace(`ZitiContext.acquireTLSHandshakeLock() [${fd}] successfully acquired _tlsHandshakeLock`);
  }
  releaseTLSHandshakeLock(fd) {
    if (isEqual(this._tlsHandshakeLockFD, fd)) {
      this.logger.trace(`ZitiContext.releaseTLSHandshakeLock() [${fd}] releasing _tlsHandshakeLock`);
      this._tlsHandshakeLockFD = undefined;
      this._tlsHandshakeLockRelease();
    }
  }


  /**
   * 
   * @param {*} wasmFD      // id of socket
   * @param {*} arrayBuffer // ArrayBuffer
   */
  async tls_enqueue(wasmInstance, wasmFD, arrayBuffer) {

    this.logger.trace(`ZitiContext.tls_enqueue() fd[${wasmFD}] [${this.truncateString(arrayBuffer.toString())}] entered`);

    this._libCrypto.tls_enqueue(wasmInstance, wasmFD, arrayBuffer);
  
  }

  /**
   * 
   * @param {*} wasmFD      // id of socket
   */
  peekTLSData(wasmInstance, wasmFD) {

    this.logger.trace(`ZitiContext.peekTLSData() fd[${wasmFD}] entered`);

    let item = this._libCrypto.peekTLSData(wasmInstance, wasmFD);
  
    this.logger.trace(`ZitiContext.peekTLSData() fd[${wasmFD}] returning[${item}]`);

    return item;
  }
  
  /**
   * 
   */
   async tls_write(wasmInstance, ssl, wireData) {

    this.logger.trace('ZitiContext.tls_write() entered, ssl, wireData: ', ssl, wireData);

    let result = this._libCrypto.tls_write(wasmInstance, ssl, wireData);

    this.logger.trace('ZitiContext.tls_write() exiting with: ', result);

    return result;
  }
  
  /**
   * 
   */
  async tls_read(wasmInstance, ssl) {

    this.logger.trace(`ZitiContext.tls_read() ssl[${ssl}]`);

    let result = await this._libCrypto.tls_read(wasmInstance, ssl);
  
    return result;
  }

  serializeQueryParams(parameters) {
    let str = [];
    for (let p in parameters) {
      if (parameters.hasOwnProperty(p)) {
        str.push(
          encodeURIComponent(p) + "=" + encodeURIComponent(parameters[p])
        );
      }
    }
    return str.join("&");
  }

  /**
   *  do_oidc_authorize
   * 
   *  Utilize Controller's HA OIDC endpoint to acquire an authID.  
   *  This code exists here, inline, instead of being in the zitiBrowzerEdgeClient, because the controller's
   *  swagger spec doesn't include the new HA OIDC endpoint refs.
   */
   async do_oidc_authorize( codeChallange ) {

    let self = this;

    let deferred = self._zitiBrowzerEdgeClient.getDeferred();

    let domain = self._zitiBrowzerEdgeClient.domain;
    domain = domain.replace(`/edge/client/v1`, `/oidc/authorize`);

    const state = generateRandomState();

    let body = {},
        queryParameters = {
          client_id:      'openziti',
          scope:          'openid offline_access',
          response_type:  'code',
          redirect_uri:   `https://${self.bootstrapperHost}`,
          code_challenge: `${codeChallange}`,
          code_challenge_method: 'S256',
          audience:       'openziti',
          state:          `${state}`,
        },
        form = {};

    let headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }

    const queryParams = this.serializeQueryParams(queryParameters);
    const urlWithParams = domain + (queryParams ? "?" + queryParams : "");

    body = { 
      urlWithParams: urlWithParams,
      method: 'GET',
      postData: null,
      headers: headers,
    };

    self._zitiBrowzerEdgeClient.request('POST', self.proxydomain, {}, body, headers, {}, form, deferred);

    return deferred.promise;
  };
  

  /**
   *  do_oidc_login_ext_jwt
   * 
   *  Utilize Controller's HA OIDC endpoint to authenticate.  
   *  This code exists here, inline, instead of being in the zitiBrowzerEdgeClient, because the controller's
   *  swagger spec doesn't include the new HA OIDC endpoint refs.
   */
   async do_oidc_login_ext_jwt(parameters) {

    let self = this;

    if (parameters === undefined) {
        parameters = {};
    }

    let deferred = self._zitiBrowzerEdgeClient.getDeferred();
    let domain = self._zitiBrowzerEdgeClient.domain;

    domain = domain.replace(`/edge/client/v1`, `/oidc/login/ext-jwt`);

    let body = {},
        queryParameters = {},
        form = {};

    let headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }
    // Pass the bearer token we got from the IdP
    headers = self._zitiBrowzerEdgeClient.setAuthHeaders(headers);

    const queryParams = this.serializeQueryParams(queryParameters);
    const urlWithParams = domain + (queryParams ? "?" + queryParams : "");

    body = { 
      urlWithParams: urlWithParams,
      method: 'POST',
      postData: parameters,
      headers: headers,
    };

    self._zitiBrowzerEdgeClient.request('POST', self.proxydomain, {}, body, headers, {}, form, deferred);

    return deferred.promise;

  };

  
  /**
   *  do_oidc_authorize_callback
   * 
   *  Utilize Controller's HA OIDC endpoint to authenticate.  
   *  This code exists here, inline, instead of being in the zitiBrowzerEdgeClient, because the controller's
   *  swagger spec doesn't include the new HA OIDC endpoint refs.
   */
   async do_oidc_authorize_callback(parameters) {

    let self = this;

    if (parameters === undefined) {
        parameters = {};
    }

    let deferred = self._zitiBrowzerEdgeClient.getDeferred();
    let domain = parameters.cb_url;

    let body = {},
        form = {};

    let headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }
    
    body = { 
      urlWithParams: domain,
      method: 'GET',
      postData: null,
      headers: headers,
    };

    self._zitiBrowzerEdgeClient.request('POST', self.proxydomain, {}, body, headers, {}, form, deferred);

    return deferred.promise;

  };

  /**
   *  do_oidc_oauth_token
   * 
   *  Utilize Controller's HA OIDC endpoint to acquire an apiToken.  
   *  This code exists here, inline, instead of being in the zitiBrowzerEdgeClient, because the controller's
   *  swagger spec doesn't include the new HA OIDC endpoint refs.
   */
  async do_oidc_oauth_token( parameters ) {

    let self = this;

    let deferred = self._zitiBrowzerEdgeClient.getDeferred();

    let domain = self._zitiBrowzerEdgeClient.domain;
    domain = domain.replace(`/edge/client/v1`, `/oidc/oauth/token`);

    let body = {},
        queryParameters = {
          client_id:      'openziti',
          grant_type:     'authorization_code',
          code:           parameters.code,
          redirect_uri:   `https://${self.bootstrapperHost}`,
          code_verifier:  parameters.code_verifier,
        },
        form = {};

    let headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }

    const queryParams = this.serializeQueryParams(queryParameters);

    self._zitiBrowzerEdgeClient.request('POST', domain, {}, body, headers, queryParameters, form, deferred);

    return deferred.promise;
  };

  /**
   *  do_oidc_token_refresh
   * 
   *  Utilize Controller's HA OIDC endpoint to acquire a refreshed apiToken.  
   *  This code exists here, inline, instead of being in the zitiBrowzerEdgeClient, because the controller's
   *  swagger spec doesn't include the new HA OIDC endpoint refs.
   */
    async do_oidc_token_refresh( ) {

      let self = this;
  
      let deferred = self._zitiBrowzerEdgeClient.getDeferred();
  
      let domain = self._zitiBrowzerEdgeClient.domain;
      domain = domain.replace(`/edge/client/v1`, `/oidc/oauth/token`);
  
      let body = {},
          queryParameters = {
            client_id:      'openziti',
            grant_type:     'refresh_token',
            refresh_token:  self._apiSession.refresh_token,
          },
          form = {};
  
      let headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      }
  
      const queryParams = this.serializeQueryParams(queryParameters);
  
      self._zitiBrowzerEdgeClient.request('POST', domain, {}, body, headers, queryParameters, form, deferred);
  
      return deferred.promise;
    };
  

  /**
   * 
   */
  async doAuthenticate(token) {

    let self = this;

    this._zitiBrowzerEdgeClient = this.createZitiBrowzerEdgeClient ({
      logger: this.logger,
      controllerApi: this.controllerApi,
      domain: this.controllerApi,
      token_type: this.token_type,
      access_token: token,
    });

    // the 'auth' body is common between the legacy and HA auth endpoints
    let auth = { 

      configTypes: [
        'ziti-tunneler-client.v1',
        'intercept.v1',
        'zrok.proxy.v1'
      ],

      envInfo: {

        // e.g.:  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36'
        arch: (typeof _ziti_realFetch !== 'undefined') ? window.navigator.userAgent : 'n/a',

        // e.g.:  'macOS', 'Linux', 'Windows'
        os: (typeof _ziti_realFetch !== 'undefined') ? (typeof navigator.userAgentData !== 'undefined' ? navigator.userAgentData.platform : 'n/a') : 'n/a'
      },

      sdkInfo: {
        type: self.sdkType,
        version: self.sdkVersion,
        branch: self.sdkBranch,
        revision: self.sdkRevision,
      },
  
    }

    // If running in an HA network, utilize Controller's HA OIDC endpoints to authenticate...
    if (this.isControllerHA() && !this.controllerCapabilitiesOIDCErrorEncountered) {

      const codeVerifier = generateRandomCodeVerifier();
      const codeChallange = await calculatePKCECodeChallenge(codeVerifier);
  
      /**
       * STEP-1
       * 
       * Do a server-side proxy to the controller to obtain an 'authRequestID'
       */
      let res = await self.do_oidc_authorize( codeChallange ).catch((error) => {
        this.controllerCapabilitiesOIDCErrorEncountered = true;
        self.logger.error( error );
      });
      let url = new URLSearchParams(res.redirectUrl.split('?')[1]); 
      const authRequestID = url.get('authRequestID');

      /**
       * STEP-2
       * 
       * Do a server-side proxy to the controller to obtain a 'callback URL'
       */
      res = await self.do_oidc_login_ext_jwt({ auth: auth, id: authRequestID }).catch((error) => {
        this.controllerCapabilitiesOIDCErrorEncountered = true;
        self.logger.error( error );
      });

      /**
       * STEP-3
       * 
       * Do a server-side proxy to the controller to obtain a 'code_resp'
       */
      res = await self.do_oidc_authorize_callback({ cb_url: res.redirectUrl }).catch((error) => {
        this.controllerCapabilitiesOIDCErrorEncountered = true;
        self.logger.error( error );
      });
      url = new URLSearchParams(res.redirectUrl.split('?')[1]); 
      const code_resp = url.get('code');

      /**
       * STEP-4
       * 
       * Finally, Do a direct call to the controller to obtain an 'access_token'
       */
      res = await self.do_oidc_oauth_token({ code: code_resp, code_verifier: codeVerifier}).catch((error) => {
        this.controllerCapabilitiesOIDCErrorEncountered = true;
        self.logger.error( error );
      });
  
      return res;
    }

    // ...otherwise, utilize Controller's "legacy"" endpoint to authenticate
    else {
      let res = await self._zitiBrowzerEdgeClient.authenticate({ 
        method: 'ext-jwt', 
        auth: auth,
        token: token
      }).catch((error) => {
        self.logger.error( error );
      });
      return res;
    }
  }

  delay(time) {
    return new Promise(resolve => setTimeout(resolve, time));
  }

  /**
   * 
   */
  async getAccessTokenEmail() {
    var decoded_access_token = jwt_decode(this.access_token);
    return decoded_access_token.email;
  }

  /**
   * 
   */
  isControllerHA() {
    return ( this.controllerCapabilities.includes(ZITI_CONSTANTS.ZITI_HA_CONTROLLER) && this.controllerCapabilities.includes(ZITI_CONSTANTS.ZITI_OIDC_AUTH) );
  }

  /**
   * 
   */
  async getFreshAPISessionWithToken(token) {

    let authenticated = false;
    let retry = 2;

    do {

      let res = await this.doAuthenticate(token);

      if (this.isControllerHA()) {

        if (isUndefined(res)) {

          this.logger.trace('ZitiContext.getFreshAPISession(): will retry after delay');
          await this.delay(1000);
          retry--;
  
        } else if (isUndefined( res.access_token )) {

            this.logger.error('response contains no access_token');
            this.logger.trace('ZitiContext.getFreshAPISession(): will retry after delay');
            await this.delay(1000);
            retry--;

        } else {
  
          /**
           * Update the edge client so that it has the new access_token from the Controller OIDC auth flow.
           * All subsequent REST calls to the controller will carry that bearer token.
           */
          this._zitiBrowzerEdgeClient = this.createZitiBrowzerEdgeClient ({
            logger: this.logger,
            controllerApi: this.controllerApi,
            domain: this.controllerApi,
            token_type: this.token_type,
            access_token: res.access_token,
          });

          this._apiSession = res;
          this._apiSession.token = res.access_token;

          authenticated = true;

          //
          async function refreshAccessToken( self ) {

            self.logger.warn("access_token is about to expire. Refreshing now...");

            let res = await self.do_oidc_token_refresh().catch((error) => {
              self.controllerCapabilitiesOIDCErrorEncountered = true;
              self.logger.error( error );
            });

            self._zitiBrowzerEdgeClient = self.createZitiBrowzerEdgeClient ({
              logger: self.logger,
              controllerApi: self.controllerApi,
              domain: self.controllerApi,
              token_type: self.token_type,
              access_token: res.access_token,
            });

            self._apiSession = res;
            self._apiSession.token = res.access_token;

            let expirationTime = self._apiSession.expires_in - 10;          // calc the moment 10 seconds before the access token expires
            setTimeout(refreshAccessToken, expirationTime * 1000, self);    // schedule the refresh
  
            /**
             * emit an event to cause the new apiSession data to ripple out to ZBR
             */
            self.emit(ZITI_CONSTANTS.ZITI_EVENT_ACCESS_TOKEN_REFRESHED, {
              token: self._apiSession.token
            });  
    
            self.updateChannelsWithUpdatedToken( self._apiSession.token );

          }

          let expirationTime = this._apiSession.expires_in - 10;            // calc the moment 10 seconds before the access token expires
          setTimeout(refreshAccessToken, expirationTime * 1000, this);      // schedule the refresh
        }

      } else {
      
        if (isUndefined(res)) {

          this.logger.trace('ZitiContext.getFreshAPISession(): will retry after delay');
          await this.delay(1000);
          retry--;

        }
        else if (!isUndefined(res.error)) {

          retry = 0;

        } else {

          this._apiSession = res.data;
          if (isUndefined( this._apiSession )) {

            this.logger.error('response contains no data');
            this.logger.trace('ZitiContext.getFreshAPISession(): will retry after delay');
            await this.delay(1000);
            retry--;

          } 
          else if (isUndefined( this._apiSession.token )) {

            this.logger.error('response contains no token');
            this.logger.trace('ZitiContext.getFreshAPISession(): will retry after delay');
            await this.delay(1000);
            retry--;

          }
          else {

            // Set the token header on behalf of all subsequent Controller API calls
            this._zitiBrowzerEdgeClient.setApiKey(this._apiSession.token, 'zt-session', false);

            setTimeout(this.apiSessionHeartbeat, this.getApiSessionHeartbeatTime(), this );

            authenticated = true;

          }

        }
      }

    } while (!authenticated && retry > 0);
  

    return authenticated;
  }

  /**
   * 
   */
  getCurrentAPISession() {
    return this._apiSession;
  }
  /**
   * 
   */
  setCurrentAPISession(apiSession) {

    this._apiSession = apiSession;

    let access_token;

    if (this.isControllerHA()) {

      access_token = this._apiSession.access_token;

    } else {

      access_token = this.access_token;

    }

    this._zitiBrowzerEdgeClient = this.createZitiBrowzerEdgeClient ({
      logger: this.logger,
      controllerApi: this.controllerApi,
      domain: this.controllerApi,
      token_type: this.token_type,
      access_token: access_token,
    });

    if (!this.isControllerHA()) {
      // Set the token header on behalf of all subsequent Controller API calls
      this._zitiBrowzerEdgeClient.setApiKey(this._apiSession.token, 'zt-session', false);
    }

  }

  /**
   * 
   */
  async getFreshAPISession() {
  
    this.logger.trace('ZitiContext.getFreshAPISession() entered');

    /**
     * Try to authenticate with the access_token first
     */
    let authenticated = await this.getFreshAPISessionWithToken(this.access_token);

    if (!authenticated) {

      /**
       * If we failed to auth with the access_token, then try to auth with the id_token
       */
      authenticated = await this.getFreshAPISessionWithToken(this.id_token);

      if (authenticated) {  
  
        /**
         * If we successfully authenticated with the id_token, emit an event to warn the
         * user that id_token auth is deprecated.
         */
//temporarily remove the deprecation notification        
        //  var decoded_access_token = jwt_decode(this.id_token);
        //  this.emit(ZITI_CONSTANTS.ZITI_EVENT_DEPRECATION_ID_TOKEN, {
        //   email: decoded_access_token.email
        // });  
      }
    }

    if (!authenticated) {
      this.logger.error(`cannot authenticate`);

        var decoded_access_token = jwt_decode(this.id_token);

        this.logger.error(`ZitiContext.getFreshAPISession(): user [${decoded_access_token.email}] authentication request failed`);

        // Let any listeners know the given JWT is not authorized to access the network,
        // which is most likely a condition where the Identity was not provisioned
        this.emit(ZITI_CONSTANTS.ZITI_EVENT_INVALID_AUTH, {
          email: decoded_access_token.email
        });

        this.delay(1000);

    }

    this.logger.trace('ZitiContext.getFreshAPISession() exiting; zt-session token is: ', this._apiSession.token);

    return this._apiSession.token ;
  }


  /**
   * 
   */
  async ensureAPISession() {
  
    let token;

    await this._ensureAPISessionMutex.runExclusive(async () => {

      if (this.isControllerHA()) {

        if (isNull( this._apiSession ) ) {
          token = await this.getFreshAPISession().catch((error) => {
            token = null;
          });
        } else {
          token = this._apiSession.access_token;
        }

      } else {

        if (isNull( this._apiSession ) || isUndefined( this._apiSession.token )) {
          token = await this.getFreshAPISession().catch((error) => {
            token = null;
          });
        } else {
          token = this._apiSession.token;
        }

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
      let certPEMArray = splitPemChain(this._certPEM);
      this._certPEMLeaf = certPEMArray[0];
      this._certPEMIntermediatesArray = certPEMArray.slice(1);
      return true;
    }

  }

  /**
   * 
   */
  async getCasPEM () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = await this.getPrivateKeyPEM(this._pkey)
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
      this._privateKeyPEM = await this.getPrivateKeyPEM(this._pkey)
    }
    if (isNull(this._certPEM)) {
      await this.enroll()
    }

    return this._certPEM;
  }

  /**
   * 
   */
  async getCertPEMLeaf () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = await this.getPrivateKeyPEM(this._pkey)
    }
    if (isNull(this._certPEMLeaf)) {
      await this.enroll()
    }

    return this._certPEMLeaf;
  }

  /**
   * 
   */
  async getCertPEMIntermediatesArray () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = await this.getPrivateKeyPEM(this._pkey)
    }
    if (isNull(this._certPEMLeaf)) {
      await this.enroll()
    }

    return this._certPEMIntermediatesArray;
  }

  /**
   * 
   */
  async getCertPEMExpiryTime () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = await this.getPrivateKeyPEM(this._pkey)
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

    let idpAuthHealthEvent = {
      expired: false    // default is to assume JWT is NOT expired
    };

    if (!isUndefined(res.error)) {

      self.logger.error(res.error.message);

      if (!isUndefined( self._apiSession )) {
        self._apiSession.token = null;
      }

      idpAuthHealthEvent.expired = true;
    
    } else {

      self._apiSession = res.data;
      if (isUndefined( self._apiSession )) {
        self.logger.warn('ZitiContext.apiSessionHeartbeat(): response contains no data:', res);
        idpAuthHealthEvent.expired = true;
      }

      if (isUndefined( self._apiSession.token )) {
        self.logger.warn('ZitiContext.apiSessionHeartbeat(): response contains no token:', res);
        idpAuthHealthEvent.expired = true;
      }

      if (Array.isArray( res.data.authQueries )) {
        forEach( res.data.authQueries, function( authQueryElement ) {
          if (isEqual(authQueryElement.typeId, 'EXT-JWT')) {
            idpAuthHealthEvent.expired = true;
          }
        });
      }

      // If we are NOT in HA mode
      if (!self.isControllerHA()) {
        // Set the token header on behalf of all subsequent Controller API calls
        self._zitiBrowzerEdgeClient.setApiKey(self._apiSession.token, 'zt-session', false);
      }

      self.logger.trace('ZitiContext.apiSessionHeartbeat() exiting; token is: ', self._apiSession.token);
    }

    // Let any listeners know the current IdP Auth health status
    self.emit(ZITI_CONSTANTS.ZITI_EVENT_IDP_AUTH_HEALTH, idpAuthHealthEvent);

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
      configTypes: 'all',
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
    // this.logger.trace('List of available Services acquired: [%o]', this._services);
    
  }


  /**
   * 
   */
  async listControllerVersion() {
     
    let self = this;

    let res = await this._zitiBrowzerEdgeClient.listVersion({ 
    }).catch((error) => {
      // Let listeners know we failed to connect to the Controller
      self.emit(ZITI_CONSTANTS.ZITI_EVENT_CONTROLLER_CONNECTION_ERROR, {
        controllerApi: self.controllerApi,
      });
      throw error;
    });

    if (!isUndefined(res.error)) {
      this.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    this._controllerVersion = res.data;
    
    if (isUndefined( this._controllerVersion ) ) {
      throw new Error('response contains no data');
    }

    this.logger.info('Controller Version acquired: ', this._controllerVersion.version);

    const {capabilities} = this._controllerVersion;
    this.controllerCapabilities = capabilities;
    this.logger.trace(`controllerCapabilities: ${this.controllerCapabilities}`);

    return this._controllerVersion;
  }

  get controllerVersion () {
    return this._controllerVersion;
  }

  /**
   * 
   */
  async listExternalJwtSigners() {
    
    let self = this;

    let res = await this._zitiBrowzerEdgeClient.listExternalJwtSigners({ 
    }).catch((error) => {
      // Let listeners know we failed to connect to the Controller
      self.emit(ZITI_CONSTANTS.ZITI_EVENT_CONTROLLER_CONNECTION_ERROR, {
        controllerApi: self.controllerApi,
      });
      throw error;
    });

    if (!isUndefined(res.error)) {
      this.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    this._externalJwtSigners = res.data;
    
    if (isUndefined( this._externalJwtSigners ) ) {
      throw new Error('response contains no data');
    }

    this.logger.info('externalJwtSigners acquired: ', this._externalJwtSigners);

    return this._externalJwtSigners;
  }
  
  /**
   * 
   */
  getExternalJwtSignerScopesByClientId(clientId) {
    let scopes = result(find(this._externalJwtSigners, function(obj) {
      return obj.clientId === clientId;
    }), 'scopes');
    this.logger.trace(`getExternalJwtSignerScopesByClientId() clientId[${clientId}] has scopes[${scopes}]`);
    return scopes;
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
    this.logger.trace(`getServiceIdByName() service[${name}] has id[${service_id}]`);
    return service_id;
  }
 

  /**
   * 
   */
  getServiceEncryptionRequiredByName (name) {
    let encryptionRequired = result(find(this._services, function(obj) {
      return obj.name === name;
    }), 'encryptionRequired');
    this.logger.trace(`getServiceEncryptionRequiredByName() service[${name}] has encryptionRequired[${encryptionRequired}]`);
    return encryptionRequired;
  }

  
  /**
   * 
   */
   async getServiceConfigByName (name) {
    if (isEqual( this._services.size, 0 )) {
      await this.fetchServices();
    }

    let serviceList = [];
    let foundService = find(this._services, function(service) {
      serviceList.push(service.name);
      return isEqual(service.name, name);  
    });
    if (!foundService) {
      // Let any listeners know the given service is not present,
      // which is most likely a condition of a misconfigured network
      this.emit(ZITI_CONSTANTS.ZITI_EVENT_NO_SERVICE, {
        serviceName: name,
        serviceList: serviceList
      });
      return undefined;
    }

    let config = result(find(this._services, function(obj) {
      return obj.name === name;
    }), 'config');
    this.logger.trace(`getServiceConfigByName() service[${name}] has config: `, config);

    if (isUndefined(config)) {
      // Let any listeners know there are no configs associated with the given service,
      // which is most likely a condition of a misconfigured network
      this.emit(ZITI_CONSTANTS.ZITI_EVENT_NO_CONFIG_FOR_SERVICE, {
        serviceName: name
      });
    }

    return config;
  }

  /**
   * 
   */
  async getConfigHostByServiceName (name) {
    let config = await this.getServiceConfigByName(name);
    let host = 'unknown';
    if (isUndefined(config)) {
      return host;
    }
    if (config['intercept.v1']) {
      host = config['intercept.v1'].addresses[0];
    } else {
      if (config['ziti-tunneler-client.v1']) {
        host = config['ziti-tunneler-client.v1'].hostname;
      }
    }
    if (isEqual(host, 'unknown')) {
      this.logger.warn(`service[${name}] has no config`);

      // Let any listeners know there are no configs associated with the given service,
      // which is most likely a condition of a misconfigured network
      this.emit(ZITI_CONSTANTS.ZITI_EVENT_CONFIG_FOR_SERVICE, {
        serviceName: name
      });
    }

    return host;
  }

  /**
   *  If scheme is 'https' then look for port 443. If 443 not found, 
   *    use portRange.low
   * 
   *  If scheme is 'http'  then look for any port that is NOT 443
   */
  getPortByScheme(portRanges, scheme) {

    let dst_port;

    scheme = scheme.replace(':', '');

    find(portRanges, function(portRange) {
      if (isEqual( scheme, 'https' )) {
        if (isEqual( portRange.low, 443 ) || isEqual( portRange.high, 443 )) {
          dst_port = 443;
          return true;
        } else {
          dst_port = portRange.low;
          return true;
        }
      }
      if (isEqual( scheme, 'http' )) {
        if (!isEqual( portRange.low, 443 )) {
          dst_port = portRange.low;
          return true;
        }
        else if (!isEqual( portRange.high, 443 )) {
          dst_port = portRange.high;
          return true;
        } else {
          dst_port = 443;
          return true;
        }
      }
    });

    return dst_port.toString();
  }

  getProtocol(protocolsArray) {
    let protocol;
    find(protocolsArray, function(p) {
      if (isEqual( p, 'tcp' )) {
        protocol = p;
        return true;
      }
    });
    return protocol;
  }

  /**
   * 
   */
  async getConnectAppDataByServiceName (name, scheme) {
    let config = await this.getServiceConfigByName(name);
    if (isUndefined(config)) {
      return undefined;
    }
    if (!config['intercept.v1']) {
      return undefined;
    }
    let dst_port = this.getPortByScheme(config['intercept.v1'].portRanges, scheme);
    let dst_protocol = this.getProtocol(config['intercept.v1'].protocols);
    if (isUndefined(dst_protocol)) {
      // Let any listeners know there are no supported protocols associated with the given service,
      // which is most likely a condition of a misconfigured network
      this.emit(ZITI_CONSTANTS.ZITI_EVENT_NO_CONFIG_PROTOCOL_FOR_SERVICE, {
        serviceName: name
      });
    }
    let appData = {
      dst_protocol: dst_protocol,
      dst_port:     dst_port,
    };
    if (isIP(config['intercept.v1'].addresses[0])) {
      appData.dst_ip = config['intercept.v1'].addresses[0];
    } else {
      appData.dst_hostname = config['intercept.v1'].addresses[0];
    }
    this.logger.trace('getConnectAppDataByServiceName returning: ', appData);
    return appData;
  }

  /**
   * 
   */
   async getConfigHostAndPortByServiceName (name) {
    let config = await this.getServiceConfigByName(name);
    let ret = undefined;
    if (!isUndefined(config)) {
      if (config['intercept.v1']) {
        ret = {
          host: config['intercept.v1'].addresses[0],
          port: config['intercept.v1'].portRanges[0].high,
        }
      } else {
        if (config['ziti-tunneler-client.v1']) {
          ret = {
            host: config['ziti-tunneler-client.v1'].hostname,
            port: config['ziti-tunneler-client.v1'].port,
          }
        } else {
          if (config['zrok.proxy.v1']) {
            return undefined;
          }
        }
      }
    }
    if (isUndefined(ret)) {
      this.logger.warn(`service[${name}] has no config`);

      // Let any listeners know there are no configs associated with the given service,
      // which is most likely a condition of a misconfigured network
      this.emit(ZITI_CONSTANTS.ZITI_EVENT_CONFIG_FOR_SERVICE, {
        serviceName: name
      });
    }

    return ret;
  }

 
  /**
   * 
   */
  async getNetworkSessionByServiceId(serviceID) {

    let self = this;

    async function _getNetworkSessionByServiceId(serviceID) {
   
      await self._getNetworkSessionByServiceIdMutex.runExclusive(async () => {
  
        // if we do NOT have a NetworkSession for this serviceId, then create it
        if (!self._network_sessions.has(serviceID)) {
  
          let network_session = await self.createNetworkSession(serviceID)
          .catch((error) => {
            self.logger.error(error);
            throw error;
          });
  
          self.logger.debug('getNetworkSessionByServiceId() Created new network_session [%o] ', network_session);
    
          self._network_sessions.set(serviceID, network_session);
        }
      
      });
  
      let netSess = self._network_sessions.get(serviceID);
  
      self.logger.debug('getNetworkSessionByServiceId() returning network_session [%o] ', netSess);
  
      return netSess;
    }
  
    if (isUndefined( this.memoized_getNetworkSessionByServiceId )) {
      this.memoized_getNetworkSessionByServiceId = memoize(_getNetworkSessionByServiceId);
    }

    return this.memoized_getNetworkSessionByServiceId(serviceID);

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

      // Let any listeners know there is most likely a condition of a misconfigured network
      this.emit(ZITI_CONSTANTS.ZITI_EVENT_SESSION_CREATION_ERROR, {
        error: res.error.message
      });
        
      this.logger.error(`ZitiContext.createSession(): ${res.error.message}`);

      return undefined;
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

    this.logger.trace(`newConnection() conn[${conn.id}]`);

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

    this.logger.debug(`dial() conn[${conn.id}] service[${service}]`);

    if (isEqual( this.services.size, 0 )) {
      await this.fetchServices();
    }

    let service_id = this.getServiceIdByName(service);
    
    conn.encrypted = this.getServiceEncryptionRequiredByName(service);

    let network_session = await this.getNetworkSessionByServiceId(service_id);

    await this.connect(conn, network_session);

    this.logger.debug(`dial() conn[${conn.id}] service[${service}] encryptionRequired[${conn.encrypted}] is now complete`);

  };

  getEdgeRouterURL(edgeRouter) {
    if (edgeRouter.urls.ws) return edgeRouter.urls.ws;
    if (edgeRouter.urls.wss) return edgeRouter.urls.wss;
    throw new Error( 'edgeRouter does not contain any browZer-compatible URLs' );
  }

 /**
  * Connect specified ZitiConnection to the nearest Edge Router.
  * 
  * @param {Array} edgeRouters
  */
  async _getPendingChannelConnects(conn, edgeRouters) {

    this.logger.trace('_getPendingChannelConnects entered');

    let pendingChannelConnects = new Array();

    let self = this;
    
    // Get a channel connection to each of the Edge Routers that have a WSS binding, initiating a connection if channel is not yet connected
    for (var i = 0; i < edgeRouters.length; i++) {
  
      self.logger.trace(`calling getChannelByEdgeRouter for wssER [${edgeRouters[i].hostname}]`);  
      let ch = await self.getChannelByEdgeRouter(conn, edgeRouters[i]).catch((err) => {
        self.logger.error( err );  
        throw new Error( err );
      });
      self.logger.debug(`initiating Hello to [${self.getEdgeRouterURL(edgeRouters[i])}] for session[${conn.networkSessionToken}]`);
      pendingChannelConnects.push( 
        ch.hello() 
      );

    };

    return pendingChannelConnects;
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
          ch.zitiContext.logger.trace(`awaitChannelConnectComplete() ch[${ch.id}] still not yet connected`);
          setTimeout(waitForChannelConnectComplete, 100);  
        } else {
          ch.zitiContext.logger.trace(`ch[${ch.id}] is connected`);
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

  
    this.logger.trace(`getChannelByEdgeRouter entered for conn[${conn.id}] edgeRouter[${edgeRouter.hostname}]`);

    let key = edgeRouter.hostname + '-' + conn.networkSessionToken;

    this.logger.trace(`getChannelByEdgeRouter key[${key}]`);

    let channelsArray = this._channels.get( key );
    if (isUndefined(channelsArray)) {
      channelsArray = new Array();
      this._channels.set(key, channelsArray);
    }
    
    // Select a Channel that is currently NOT in use (has no active Connections on it)
    let freeChannel;
    find(channelsArray, function(ch) {
      // let activeConnectionCount = ch._connections._items.size;
      // if (isEqual( activeConnectionCount, 0 )) {
        freeChannel = ch;
        return true;
      // }
    });


    // let ch = this._channels.get( key );
    let ch = freeChannel;

    if (!isUndefined(ch)) {

      this.logger.trace(`ch[${ch.id}] state[${ch.state}] found for edgeRouter[${edgeRouter.hostname}]`);

      await this.awaitChannelConnectComplete(ch);

      this.logger.trace(`ch[${ch.id}] state[${ch.state}] for edgeRouter[${edgeRouter.hostname}] is connect-complete`);

      if (!isEqual( ch.state, ZitiEdgeProtocol.conn_state.Connected )) {
        this.logger.error(`should not be here: ch[${ch.id}] has state[${ch.state}]`);
      }

      this.logger.trace(`getChannelByEdgeRouter returning existing ch[${ch.id}]`);

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

    this.logger.trace(`Created ch[${ch.id}]`);
    channelsArray.push(ch);

    this.logger.trace(`getChannelByEdgeRouter channelsArray length [${channelsArray.length}] items`);
    
    this.logger.trace(`getChannelByEdgeRouter returning new ch[${ch.id}]`);

    return ch;
  }
 
  /**
   * 
   */
  addWASMFD(socket) {

    let wasmFD = new ZitiWASMFD({
      id: this.getNextWASMFDId(),
      socket: socket
    });

    this._wasmFDsById.set(wasmFD.id, wasmFD);

    return wasmFD.id;
  }

  /**
   * 
   */
  findChannelByEdgeRouter(edgeRouter) {

    throwIf(isUndefined(edgeRouter), 'edgeRouter not specified');

    let result = {};

    find(Array.from(this._channels), function(obj) {
      if (isEqual( obj[1][0]._edgeRouterHost, edgeRouter )) {
        result.key = obj[0];
        result.ch = obj[1];
        return true;
      }
    });
  
    return result;
  }

  activeChannelCount() {
    return this._channels.size;
  }
 
  /**
   * 
   */
  updateChannelsWithUpdatedToken( apiSessionToken ) {

    find(Array.from(this._channels), function(obj) {
      obj[1][0].updateToken( apiSessionToken ) 
    });
  
  }


 /**
  * Connect specified ZitiConnection to the nearest Edge Router.
  * 
  * @param {ZitiConnection} conn
  * @param {*} networkSession
  */
  async connect(conn, networkSession) {

    let self = this;
   
    this.logger.debug(`ctx.connect() conn[${conn.id}] socket[${conn.socket._id}] networkSession[${networkSession}]`);  
    
    conn.networkSessionToken = networkSession.token;
  
    // Get list of all Edge Router URLs where the Edge Router has a WS binding
    let edgeRouters = filter(networkSession.edgeRouters, function(o) { 
      return (has(o, 'urls.ws') || has(o, 'urls.wss')); 
    });
    this.logger.trace(`edgeRouters [${edgeRouters}]`);  

    // Something is wrong if we have no ws-enabled edge routers
    if (isEqual(edgeRouters.length, 0)) {
      // Let any listeners know we have no ws-enabled edge routers in the network
      this.emit(ZITI_CONSTANTS.ZITI_EVENT_NO_WSS_ROUTERS, {} );
      throw new Error(`No Edge Routers with 'wss:' binding were found`);
    }
  
    //
    // this.logger.debug(`trying to acquire _connectMutex for conn[${conn.id}]`);
  
    // await this._connectMutexWithTimeout.runExclusive(async () => {
  
      // this.logger.debug(`now own _connectMutex for conn[${conn.id}]`);
  
      let pendingChannelConnects = await this._getPendingChannelConnects(conn, edgeRouters);

      let nearestEdgeRouter;

      if (!this._didInitialGetPendingChannelConnects) {

        // The first time through, we will only wait for one wssER connect to complete, and
        // will select it as the "nearest".  Other, slower, wssER connects will continue to
        // run, and eventually complete in the background, but we will not wait for them here
        // since that would impede performance.
        nearestEdgeRouter = await Promise.race( pendingChannelConnects );

        this.logger.trace(`Promise.race helloCompletedDuration time for wssER[${nearestEdgeRouter.edgeRouterHost}] was [${nearestEdgeRouter.helloCompletedDuration}]`);

        this._didInitialGetPendingChannelConnects = true;

      } else {

        // Subsequently, we will wait for all wssER connects to complete, since they 
        // will most likely have done so before we get back here.  We will then examine
        // the helloCompletedDuration values across all wssERs and chose the one with
        // the lowest value.

        let edgeRouterConnects = await Promise.all( pendingChannelConnects );

        let helloCompletedDuration = 999999999999;

        find(edgeRouterConnects, function(edgeRouterConnect) {
          self.logger.trace(`Promise.all helloCompletedDuration time for wssER[${edgeRouterConnect.edgeRouterHost}] was [${edgeRouterConnect.helloCompletedDuration}]`);
          if (edgeRouterConnect.helloCompletedDuration < helloCompletedDuration) {
            nearestEdgeRouter = edgeRouterConnect;
            helloCompletedDuration = edgeRouterConnect.helloCompletedDuration;
          }
        });

      }

      let channelWithNearestEdgeRouter = nearestEdgeRouter.channel;
      channelWithNearestEdgeRouter._connections._saveConnection(conn);
      conn.channel = channelWithNearestEdgeRouter;
      this.logger.debug(`ctx.connect() conn[${conn.id}] socket[${conn.socket._id}] ch[${channelWithNearestEdgeRouter.id}] has nearest wssER[${nearestEdgeRouter.edgeRouterHost}]`);
  
      // Initiate connection with Edge Router (creates Fabric session)
      // if (conn.socket.isNew) {
        await channelWithNearestEdgeRouter.connectWithRetry(conn).catch(( error ) => { 
          this.logger.trace(`ctx.connect() conn[${conn.id}] error[${error.message}]`);
        });
      // }
  
      if (conn.state == ZitiEdgeProtocol.conn_state.Connected) {
        if (conn.encrypted) {  // if connected to a service that has 'encryptionRequired'
          // Do not proceed until crypto handshake has completed
          this.logger.trace(`ctx.connect() conn[${conn.id}] socket[${conn.socket._id}] awaitConnectionCryptoEstablishComplete start`);
          await channelWithNearestEdgeRouter.awaitConnectionCryptoEstablishComplete(conn);
          this.logger.trace(`ctx.connect() conn[${conn.id}] socket[${conn.socket._id}] awaitConnectionCryptoEstablishComplete end`);
        }
      }
      // this.logger.debug(`releasing _connectMutex for conn[${conn.id}]`);
    // })
    // .catch(( err ) => {
    //   this.logger.error(err);
    //   throw new Error(err);
    // });  
  }


 /**
  * Determine if the given URL should be routed over Ziti.
  * 
  * @param {*} url
  */
  async shouldRouteOverZiti(url) {

    let self = this;

    async function _shouldRouteOverZiti(url) {
     
      let parsedURL = new URL(url);
   
      let hostname = parsedURL.hostname;
      let port = parsedURL.port;
    
      if (port === '') {
        if ((parsedURL.protocol === 'https:') || (parsedURL.protocol === 'wss:')) {
          port = 443;
        } else {
          port = null;
        }
      }
      
      let serviceName = await self.getServiceNameByHostNameAndPort(hostname, port).catch(( error ) => {
        throw new Error( error );
      });
  
      if (parsedURL.port === '') {

        if (isUndefined(serviceName)) {
    
          serviceName = await self.getServiceNameByHostName(hostname).catch(( error ) => {
            throw new Error( error );
          });
      
        }

      }

      if (isUndefined(serviceName)) {
        serviceName = self.shouldRouteOverZitiSync(url);
      }

      return serviceName;
     
    }
  
    if (isUndefined( this.memoized_shouldRouteOverZiti )) {
      this.memoized_shouldRouteOverZiti = memoize(_shouldRouteOverZiti);
    }

    return this.memoized_shouldRouteOverZiti(url);
   
  }

  shouldRouteOverZitiSync(url) {

    let parsedURL = new URL(url);   
    let hostname = parsedURL.hostname;
    let port = parseInt(parsedURL.port, 10);
    if ((port === '') || (parsedURL.port === '')) {
      if ((parsedURL.protocol === 'https:') || (parsedURL.protocol === 'wss:')) {
        port = 443;
      } else {
        port = 80;
      }
    }

    let self = this;

    let serviceName = result(find(this._services, function(obj) {
  
      if (self._getMatchConfigTunnelerClientV1( obj.config['ziti-tunneler-client.v1'], hostname, port )) {
        return true;
      }

      if (self._getMatchConfigInterceptV1( obj.config['intercept.v1'], hostname, port )) {
        return true;
      }

    }), 'name');

    return serviceName;

  }

 /**
  * Determine if the given URL should be handled via CORS Proxy.
  * 
  */
  shouldRouteOverCORSProxy(url) {

    let parsedURL = new URL(url);
  
    let hostname = parsedURL.hostname;
    let port = parseInt(parsedURL.port, 10);
  
    if ((port === '') || (parsedURL.port === '')) {
      if ((parsedURL.protocol === 'https:') || (parsedURL.protocol === 'wss:')) {
        port = 443;
      } else {
        port = 80;
      }
    }
  
    let corsHostsArray = window.zitiBrowzerRuntime.zitiConfig.browzer.bootstrapper.corsProxy.hosts.split(',');
  
    let routeOverCORSProxy = false;
    forEach(corsHostsArray, function( corsHost ) {
      let corsHostSplit = corsHost.split(':');
      if ((hostname === corsHostSplit[0]) && (port === parseInt(corsHostSplit[1], 10))) {
        routeOverCORSProxy = true;
      }
    });
    return routeOverCORSProxy;
  }
 

  /**
   * 
   * @param {*} hostname 
   * @param {*} port 
   * @returns 
   */
   async getServiceNameByHostName(hostname) {

    let self = this;
    hostname = decodeURIComponent(hostname);

    async function _getServiceNameByHostName(hostname) {

      await self._getServiceNameByHostNameAndPortMutex.runExclusive(async () => {
        if (isEqual( self.services.size, 0 )) {
          await self.fetchServices().catch((error) => {
            throw new Error(error);
          });
        }
      });
  
      let serviceName = result(find(self._services, function(obj) {
  
        if (isEqual( obj.name.toLowerCase(), hostname )) {
          return true;
        }
  
      }), 'name');
  
      return serviceName;
    }

    if (isUndefined( this.memoized_getServiceNameByHostName )) {
      this.memoized_getServiceNameByHostName = memoize(_getServiceNameByHostName);
    }

    return await this.memoized_getServiceNameByHostName(hostname);
  }


  /**
   * 
   * @param {*} hostname 
   * @param {*} port 
   * @returns 
   */
  async getServiceNameByHostNameAndPort(hostname, port) {

    let self = this;
    hostname = decodeURIComponent(hostname);

    async function _getServiceNameByHostNameAndPort(hostname, port) {

      if (typeof port === 'string') {
        port = parseInt(port, 10);
      }
  
      await self._getServiceNameByHostNameAndPortMutex.runExclusive(async () => {
        if (isEqual( self.services.size, 0 )) {
          await self.fetchServices().catch((error) => {
            throw new Error(error);
          });
        }
      });
    
      let serviceName = result(find(self._services, function(obj) {
  
        if (self._getMatchConfigTunnelerClientV1( obj.config['ziti-tunneler-client.v1'], hostname, port )) {
          return true;
        }
  
        if (self._getMatchConfigInterceptV1( obj.config['intercept.v1'], hostname, port )) {
          return true;
        }
  
      }), 'name');
  
      return serviceName;
    }
  
    if (isUndefined( this.memoized_getServiceNameByHostNameAndPort )) {
      this.memoized_getServiceNameByHostNameAndPort = memoize(_getServiceNameByHostNameAndPort);
    }

    return await this.memoized_getServiceNameByHostNameAndPort(hostname, port);
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
    if (!isNull(port) && config.port !== port) {
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
    let foundAddress = find(config.addresses, function(address) {
      return isEqual(address, hostname);  
    });

    if (!foundAddress) {
        return false;
    }

    if (!isNull(port)) {
      let foundPort = find(config.portRanges, function(portRange) {
        return ((port >= portRange.low) && (port <= portRange.high));
      });

      if (!foundPort) {
        return false;
      }
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
 
  /**
   * 
   */
  getNextWASMFDId() {
    this._wasmFDSeq++;
    return this._wasmFDSeq;
  }

  closeChannelByEdgeRouter( edgeRouter ) {
    let result = this.findChannelByEdgeRouter(edgeRouter);
    if (result.key && result.ch) {
      result.ch[0]._state = ZitiEdgeProtocol.conn_state.Closed;
      this._channels.delete( result.key );  
      this._channelsById.delete( result.ch[0].id );
      this.logger.warn(`channel [${result.key}] id[${result.ch[0].id}] deleted`);
    }
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

    setTimeout(async (self, ch, conn) => {
      await ch.close(conn);
      self.logger.trace(`ZitiConnection.close: conn.id[${conn.id}]`);
      ch._connections._deleteConnection(conn);
      self.logger.trace(`ZitiConnection.close: ch._connections.length is now [${ch._connections._items.size}]`);
    }, 500, this, ch, conn);

  }
 
  /**
   * 
   */
  truncateString(str, num) {
    let maxLength = num ? num : 80;
    if (str.length <= maxLength) {
      return str
    }
    return str.slice(0, maxLength) + '...'
  }
  
  /**
   * 
   * @param {*} options 
   * @returns Response
   */
   async httpFetch (url, opts) {

    let et = ElapsedTime.new().start();

    let self = this;

    let value, release;

    // if (isEqual(opts.serviceScheme, 'https')) {
    //   [value, release] = await self._fetchSemaphoreHTTPS.acquire();
    // } else {
    //   [value, release] = await self._fetchSemaphoreHTTP.acquire();
    // }

    let ret;

    let fetchPromise = new Promise( async (resolve, reject) => {

      /**
       * ------------ Now Routing over Ziti -----------------
       */
      let parsedURL = new URL(url);
      if (isEqual(parsedURL.pathname, '/')) {
        parsedURL.pathname = opts.servicePath;
        url = parsedURL.toString();
      }

      self.logger.debug(`httpFetch starting url[${url}]`);

      // build HTTP request object
      let request = new ZitiHttpRequest(opts.serviceName, url, opts, this);
      let options = await request.getRequestOptions();

      options.headers.set('Host', await this.getConfigHostByServiceName (opts.serviceName));

      let req;

      try {

        if (options.method === 'GET') {
    
          req = http.get(options);
          req.agent = await this.getZitiAgentPool().connect(req, options);
    
        } else {

          req = http.request(options);
          req.agent = await this.getZitiAgentPool().connect(req, options);

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
              let buffer;
              if (options.body.arrayBuffer) {
                let ab = await options.body.arrayBuffer();
                buffer = new Buffer(ab)
              } else {
                buffer = options.body;
              }
              req.end( buffer );
            }
          } else {
            req.end();
          }
    
        }
      }
      catch (error) {
        let errResponse = new Response(new Blob(), { status: 400, statusText: `ZBR Error: ${error}` });
        resolve(errResponse);  
      }

      req.on('error', err => {
        self.logger.error('conn[%o] error EVENT: err: %o', req.socket.zitiConnection.id, err);
        reject(new Error(`conn[${req.socket.zitiConnection.id}] request to ${req.url} failed, reason: ${err.message}`));
      });
  
      req.on('response', async res => {

        self.logger.debug(`httpFetch on.response() elapsed[${et.getValue()}] url[${url}]`);
  
        const response_options = {
          url: url,
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          size: request.size,
          timeout: request.timeout,
          counter: request.counter
        };

        let response;
        if (isEqual(res.statusCode, 204)) {
          response = new HttpResponse(null, response_options);
        } else {
          let body = res.pipe(new PassThrough( response_options, { zitiContext: res.socket.zitiContext } ));
          response = new HttpResponse(body, response_options);
        }
  
        for (const hdr in response_options.headers) {
          if (response_options.headers.hasOwnProperty(hdr)) {
            if (hdr === 'set-cookie') {
              let cookieArray = response_options.headers[hdr];
              let cookiePath;
              let expires;
              let httpOnly = false;
  
              let condensedCookieArray = new Map();

              for (let i = 0; i < cookieArray.length; i++) {
  
                let cookie = cookieArray[i];
                let name = cookie.substring(0, cookie.indexOf("="));
                let value = cookie.substring(cookie.indexOf("=") + 1);
                let cookie_value = value.substring(0, value.indexOf(";"));
                if (cookie_value !== ''){
                  let parts = value.split(";");
                  for (let j = 0; j < parts.length; j++) {
                    let part = parts[j].trim();
                    if ( part.trim().toLowerCase().startsWith("path") ) {
                      cookiePath = part.substring(part.indexOf("=") + 1);
                    }
                    else if ( part.trim().toLowerCase().startsWith("expires") ) {
                      expires = new Date( part.substring(part.indexOf("=") + 1) );
                    }
                    else if ( part.startsWith("HttpOnly") ) {
                      httpOnly = true;
                    }
                  }
  
                  condensedCookieArray.set(name, {name: name, cookie_value: cookie_value, expires: expires, cookiePath: cookiePath});
                }
              }

              function setCondensedCookies(value, key) {
                Cookies.set(value.name, value.cookie_value, { expires: value.expires, path: value.cookiePath});
              }
              condensedCookieArray.forEach(setCondensedCookies);
            }
          }
        }
        
        resolve(response);
      });
  
    });

    ret = await fetchPromise;

    return ret;
  }

}

// Export class
export default ZitiContext

