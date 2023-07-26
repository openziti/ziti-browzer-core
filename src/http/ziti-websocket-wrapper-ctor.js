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

import { ZitiWebSocketWrapper } from './ziti-websocket-wrapper';

/**
 * ZitiWebSocketWrapperCtor:
 * 
 */
class ZitiWebSocketWrapperCtor {

  /**
   * Create a new `ZitiWebSocketWrapper`.
   *
   */
  constructor(address, protocols, options) {

    // It is assumed that the ziti-browzer-runtime has already initialized before we get here

    // We only want to intercept WebSockets that target the Ziti BrowZer Bootstrapper
    var regex = new RegExp( zitiBrowzerRuntime.zitiConfig.browzer.bootstrapper.self.host, 'g' );

    if (address.match( regex )) { // the request is targeting the Ziti BrowZer Bootstrapper

      let ws = new ZitiWebSocketWrapper(address, protocols, options, zitiBrowzerRuntime.zitiContext, zitiBrowzerRuntime.zitiConfig);

      return ws;

    } else {

      return new window._ziti_realWebSocket(address, protocols, options);

    }

  }
}

export {
  ZitiWebSocketWrapperCtor
};
