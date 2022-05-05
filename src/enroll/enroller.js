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
import {
  convertPemToCertificate,
  printCertificate,
  getExpiryTimeFromCertificate,
  getBecomesUsableTimeFromCertificate,
  getBecomesUsableStringFromCertificate
} from '../utils/pki';
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

    // Don't proceed until we have successfully logged in to Controller and have established an API session
    await this.zitiContext.ensureAPISession();
    
    this.generateCSR();

    await this.createEphemeralCert();

  }


  /**
   * 
   */
  generateCSR() {

    this._csr = this.zitiContext.createCertificateSigningRequest({
      key: this.zitiContext.pKey,
    })
    
  }


  /**
   * 
   */
  async createEphemeralCert() {
  
    let res = await this.zitiContext._zitiBrowzerEdgeClient.createCurrentApiSessionCertificate({
      sessionCertificate: { 
        csr:  this._csr
      }
    }).catch((error) => {
      throw error;
    });

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
      
    let flatcert = this._cert.replace(/\\n/g, '\n');

    let certificate;
    try {
      certificate = convertPemToCertificate( flatcert );
      // printCertificate( certificate );
    } catch (err) {
      this.logger.error(err);
      this.logger.error('zitiBrowzerEdgeClient.createCurrentApiSessionCertificate returned cert [%o] which convertPemToCertificate cannot process', this._cert);
      throw new Error('zitiBrowzerEdgeClient.createCurrentApiSessionCertificate returned cert which convertPemToCertificate cannot process');
    }

    let expiryTime = getExpiryTimeFromCertificate(certificate);
    let expiryDate = new Date(expiryTime);

    let becomesUsableTime = getBecomesUsableTimeFromCertificate(certificate);
    let becomesUsableTimeString = getBecomesUsableStringFromCertificate(certificate);
    let now = new Date();
    let nowTime = now.getTime();
    this.logger.info('zitiBrowzerEdgeClient.createCurrentApiSessionCertificate returned cert with NotBefore time [%o][%o], it is now [%o][%o], difference of [%o]', becomesUsableTime, becomesUsableTimeString, nowTime, now, (nowTime-becomesUsableTime));
    if (nowTime < becomesUsableTime) {
      this.logger.error('zitiBrowzerEdgeClient.createCurrentApiSessionCertificate returned cert with NotBefore IN THE FUTURE', becomesUsableTimeString);
    }

    this.logger.debug('zitiBrowzerEdgeClient.createCurrentApiSessionCertificate returned cert with expiryTime: [%o] expiryDate:[%o]', expiryTime, expiryDate);

    this._certExpiryTime = expiryTime;
  }
  
  /**
   * 
   */
  get certPEM () {

    if (isUndefined(this._cert)) {
      throw new Error('enroller contains no certificate; Ephemeral Cert creation needed');
    }

    return this._cert;
  }

  /**
   * 
   */
   get certPEMExpiryTime () {

    if (isUndefined(this._cert)) {
      throw new Error('enroller contains no certificate; Ephemeral Cert creation needed');
    }

    return this._certExpiryTime;
  }


}

// Export class
export {
  ZitiEnroller
}

