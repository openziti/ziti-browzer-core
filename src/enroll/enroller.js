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
import { isUndefined, isNull } from 'lodash-es';



/**
 *    ZitiEnroller
 */
 class ZitiEnroller {

  /**
   * 
   */
  constructor(options) {

    let _options = flatOptions(options, defaultOptions);

    this.zitiContext = _options.zitiContext;
    this.logger = _options.logger;

  }


  /**
   * 
   */
   async initialize() {

    /* this is a nop for now */

  }


  /**
   * 
   */
  async enroll() {

    this.logger.trace('ZitiEnroller.enroll() entered');

    // Don't proceed until we have successfully logged in to Controller and have established an API session
    await this.zitiContext.ensureAPISession();
    
    this.generateCSR();

    await this.createEphemeralCert();

    this.logger.trace('ZitiContext.enroll() exiting');
  }


  /**
   * 
   */
  generateCSR() {

    this.logger.trace('ZitiEnroller.generateCSR() entered');

    this._csr = this.zitiContext.createCertificateSigningRequest({
      key: this.zitiContext.ecKey,
    })
    
    this.logger.trace('ZitiEnroller.generateCSR() exiting');
  }


  /**
   * 
   */
  async createEphemeralCert() {
  
    this.logger.trace('ZitiEnroller.createEphemeralCert() entered');

    let res = await this.zitiContext._zitiBrowzerEdgeClient.createCurrentApiSessionCertificate({
      sessionCertificate: { 
        csr:  this._csr
      }
    }).catch((error) => {
      throw error;
    });

    this.logger.trace('ZitiEnroller.createEphemeralCert(): response:', res);

    if (!isUndefined(res.error)) {
      this.logger.error(res.error.message);
      throw new Error(res.error.message);
    }

    if (isUndefined( res.data )) {
      throw new Error('response contains no data');
    }

    if (isUndefined( res.data.certificate )) {
      throw new Error('response contains no certificate; Ephemeral Cert creation failed');
    }
  
    this._cert = res.data.certificate;

    this.logger.trace('ZitiContext.createEphemeralCert() exiting');
      
  }
  

}

// Export class
export {
  ZitiEnroller
}

