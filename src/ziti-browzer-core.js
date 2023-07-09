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


import ZitiContext from './context/context.js';
import ZitiLogger from './logger/logger.js';


/**
 * 
 */
class ZitiBrowzerCore {

  /**
   * 
   */
  constructor (options = {}) {

  }

  /**
   * 
   */
  createZitiContext (options) {

    if (this._zitiContext !== undefined) {
      throw Error("Already have a ZitiContext; Cannot call .createZitiContext() twice on instance.");
    }

    this._zitiContext = new ZitiContext(Object.assign({
      logger: options.logger,
      controllerApi: options.controllerApi,
    }, options))

    return this._zitiContext;
  }

  /**
   * 
   * @param {*} defaults 
   * @returns ZitiContext
   */
  createZitiContextWithDefaults (defaults) {
    return this.ZitiContext({
      defaults: Object.assign({}, this._defaults, defaults)
    })
  }

  get context () {
    return this._zitiContext;
  }


  /**
   * 
   * @param {*} options 
   * @returns ZitiLogger
   */
  createZitiLogger (options) {

    if (this._zitiLogger !== undefined) throw Error("Already have a ZitiLogger; Cannot call .createZitiLogger() twice on instance.");

    this._zitiLogger = new ZitiLogger(Object.assign({
      logLevel: this._logLevel,
    }, options))

    return this._zitiLogger;
  }
  
  /**
   * 
   * @returns ZitiLogger
   */
  createZitiLoggerWithDefaults () {
    this._zitiLogger = this.createZitiLogger({
      logLevel: 'Silent',
    })
    return this._zitiLogger;
  }
  
  get logger () {
    if (this._zitiLogger === undefined) {
      this._zitiLogger = createZitiLoggerWithDefaults();
    }
    return this._zitiLogger;
  }
  
}

export {
  ZitiBrowzerCore
};
