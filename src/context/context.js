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
import { ZitiEnroller } from '../enroll/enroller';
import { ZitiConnection } from '../channel/connection'
import { ZitiEdgeProtocol } from '../channel/protocol';
import { ZitiChannel } from '../channel/channel'
import throwIf from '../utils/throwif';
import { ZITI_CONSTANTS } from '../constants';

import { LibCrypto } from '@openziti/libcrypto-js'
import { ZitiBrowzerEdgeClient } from '@openziti/ziti-browzer-edge-client'
import {Mutex, withTimeout} from 'async-mutex';
import { isUndefined, isEqual, isNull, result, find, filter, has } from 'lodash-es';

 
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
    this._certPEM = null;

    this._timeout = ZITI_CONSTANTS.ZITI_DEFAULT_TIMEOUT;

  }

  get libCrypto () {
    return this._libCrypto;
  }

  get timeout() {
    return this._timeout;
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

    if (isNull(this._ecKey)) {
      this.logger.trace('ZitiContext.get ecKey() needs to genetrate a new key');
      this._ecKey = this.generateECKey({});      
    }

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

    this._certPEM = this._zitiEnroller.certPEM;

  }

  /**
   * 
   */
  async getCertPEM () {

    if (isNull(this._privateKeyPEM)) {
      this._privateKeyPEM = this.getPrivateKeyPEM(this._ecKey)
    }
    if (isNull(this._certPEM)) {
      await this.enroll()
    }

    return this._certPEM;
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
   * @return {ZitiConection}
   */
  newConnection(data) {

    let conn = new ZitiConnection({ 
      zitiContext: this,
      data: data
    });

    this.logger.trace('newConnection: conn[%d]', conn.id);

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

    this.logger.debug('dial: conn[%d] service[%s] encryptionRequired[%o] is now complete', conn.id, service, conn.getEncrypted());

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

      if (!isEqual( ch.state, ZitiEdgeProtocol.conn_state.Connected )) {
        this.logger.error('should not be here: ch[%d] has state[%d]', ch.id, ch.state);
      }

      return resolve(ch);
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
    
    this.logger.trace('getChannelByEdgeRouter returning ch[%o]', ch);

    return ch;
  }
 
 

 /**
  * Connect specified ZitiConnection to the nearest Edge Router.
  * 
  * @param {ZitiConnection} conn
  * @param {*} networkSession
  * @returns {bool}
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
      let channelConnectWithNearestEdgeRouter = minby(channelConnects, function(channelConnect) { 
        return channelConnect.channel.helloCompletedTimestamp;
      });
      
      let channelWithNearestEdgeRouter = channelConnectWithNearestEdgeRouter.channel;
      this.logger.debug('Channel [%d] has nearest Edge Router for conn[%o]', channelWithNearestEdgeRouter.id, conn.id);
      channelWithNearestEdgeRouter._connections._saveConnection(conn);
      conn.channel = channelWithNearestEdgeRouter;
  
      // Initiate connection with Edge Router (creates Fabric session)
      await channelWithNearestEdgeRouter.connect(conn);
  
      if (conn.state == edge_protocol.conn_state.Connected) {
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
 
 

}

// Export class
export default ZitiContext

