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

import { flatOptions } from '../utils/flat-options'
import { defaultOptions } from './options'
import { normalizeLogLevel } from '../logLevels'
import Types from '../types'
import { isLogObj } from '../utils/index'
import ZitiReporter from '../reporters/zitiReporter.js'


 
let paused = false
const queue = []


/**
 *    ZitiLogger
 */
class ZitiLogger {

  /**
   *  ctor
   * 
   *  @param {Options} [options]
   */
  constructor(options) {

    let _options = flatOptions(options, defaultOptions);

    this._suffix = _options.suffix || ''
    this._reporters = _options.reporters || [new ZitiReporter({
      suffix: this._suffix, 
      useSWPostMessage: _options.useSWPostMessage,
      zitiBrowzerServiceWorkerGlobalScope: _options.zitiBrowzerServiceWorkerGlobalScope,
    })]
    this._types = _options.types || Types
    this._logLevel = normalizeLogLevel(_options.logLevel, this._types)
    this._defaults = _options.defaults || {_logLevel: 0}
    this._async = _options.async !== undefined ? _options.async : undefined
    this._stdout = _options.stdout
    this._stderr = _options.stderr
    this._mockFn = _options.mockFn
    this._throttle = _options.throttle || 1000
    this._throttleMin = _options.throttleMin || 5

    // Create logger functions for current instance
    for (const type in this._types) {
      const defaults = {
        type,
        ...this._types[type],
        ...this._defaults
      }
      this[type] = this._wrapLogFn(defaults)
      this[type].raw = this._wrapLogFn(defaults, true)
    }

    // Use _mockFn if is set
    if (this._mockFn) {
      this.mockTypes()
    }

    // Keep serialized version of last log
    this._lastLogSerialized = undefined
    this._lastLog = undefined
    this._lastLogTime = undefined
    this._lastLogCount = 0
    this._throttleTimeout = undefined

  }

  get logLevel () {
    return this._logLevel
  }

  set logLevel (logLevel) {
    this._logLevel = normalizeLogLevel(logLevel, this._types)
  }

  get stdout () {
    return this._stdout || console._stdout // eslint-disable-line no-console
  }

  get stderr () {
    return this._stderr || console._stderr // eslint-disable-line no-console
  }

  create (options) {
    return new ZitiLogger(Object.assign({
      logLevel: this._logLevel,
      domain: this._domain,
      defaults: this._defaults,
    }, options))
  }

  createWithDefaults (defaults) {
    return this.create({
      defaults: Object.assign({}, this._defaults, defaults)
    })
  }

  createWithTag (tag) {
    return this.createWithDefaults({
      tag: this._defaults.tag ? (this._defaults.tag + ':' + tag) : tag
    })
  }

  addReporter (reporter) {
    this._reporters.push(reporter)
    return this
  }

  removeReporter (reporter) {
    if (reporter) {
      const i = this._reporters.indexOf(reporter)
      if (i >= 0) {
        return this._reporters.splice(i, 1)
      }
    } else {
      this._reporters.splice(0)
    }
    return this
  }

  setReporters (reporters) {
    this._reporters = Array.isArray(reporters)
      ? reporters
      : [reporters]
    return this
  }

  wrapAll () {
    this.wrapConsole()
    this.wrapStd()
  }

  restoreAll () {
    this.restoreConsole()
    this.restoreStd()
  }

  wrapConsole () {
    for (const type in this._types) {
      // Backup original value
      if (!console['__' + type]) { // eslint-disable-line no-console
        console['__' + type] = console[type] // eslint-disable-line no-console
      }
      // Override
      console[type] = this[type].raw // eslint-disable-line no-console
    }
  }

  restoreConsole () {
    for (const type in this._types) {
      // Restore if backup is available
      if (console['__' + type]) { // eslint-disable-line no-console
        console[type] = console['__' + type] // eslint-disable-line no-console
        delete console['__' + type] // eslint-disable-line no-console
      }
    }
  }

  wrapStd () {
    this._wrapStream(this.stdout, 'log')
    this._wrapStream(this.stderr, 'log')
  }

  _wrapStream (stream, type) {
    if (!stream) {
      return
    }

    // Backup original value
    if (!stream.__write) {
      stream.__write = stream.write
    }

    // Override
    stream.write = (data) => {
      this[type].raw(String(data).trim())
    }
  }

  restoreStd () {
    this._restoreStream(this.stdout)
    this._restoreStream(this.stderr)
  }

  _restoreStream (stream) {
    if (!stream) {
      return
    }

    if (stream.__write) {
      stream.write = stream.__write
      delete stream.__write
    }
  }

  pauseLogs () {
    paused = true
  }

  resumeLogs () {
    paused = false

    // Process queue
    const _queue = queue.splice(0)
    for (const item of _queue) {
      item[0]._logFn(item[1], item[2])
    }
  }

  mockTypes (mockFn) {
    this._mockFn = mockFn || this._mockFn

    if (typeof this._mockFn !== 'function') {
      return
    }

    for (const type in this._types) {
      this[type] = this._mockFn(type, this._types[type]) || this[type]
      this[type].raw = this[type]
    }
  }

  _wrapLogFn (defaults, isRaw) {
    return (...args) => {
      if (paused) {
        queue.push([this, defaults, args, isRaw])
        return
      }
      return this._logFn(defaults, args, isRaw)
    }
  }

  _logFn (defaults, args, isRaw) {
    if (defaults.level > this._logLevel) {
      return this._async ? Promise.resolve(false) : false
    }

    // Construct a new log object
    const logObj = Object.assign({
      date: new Date(),
      args: []
    }, defaults)

    // Consume arguments
    if (!isRaw && args.length === 1 && isLogObj(args[0])) {
      Object.assign(logObj, args[0])
    } else {
      logObj.args = Array.from(args)
    }

    // Aliases
    if (logObj.message) {
      logObj.args.unshift(logObj.message)
      delete logObj.message
    }
    if (logObj.additional) {
      if (!Array.isArray(logObj.additional)) {
        logObj.additional = logObj.additional.split('\n')
      }
      logObj.args.push('\n' + logObj.additional.join('\n'))
      delete logObj.additional
    }

    // Normalize type and tag to lowercase
    logObj.type = typeof logObj.type === 'string' ? logObj.type.toLowerCase() : ''
    logObj.tag = typeof logObj.tag === 'string' ? logObj.tag.toLowerCase() : ''

    // Resolve log
    /**
     * @param newLog false if the throttle expired and
     *  we don't want to log a duplicate
     */
    const resolveLog = (newLog = false) => {
      const repeated = this._lastLogCount - this._throttleMin
      if (this._lastLog && repeated > 0) {
        const args = [...this._lastLog.args]
        if (repeated > 1) {
          args.push(`(repeated ${repeated} times)`)
        }
        this._log({ ...this._lastLog, args })
        this._lastLogCount = 1
      }

      // Log
      if (newLog) {
        this._lastLog = logObj
        if (this._async) {
          return this._logAsync(logObj)
        } else {
          this._log(logObj)
        }
      }
    }

    // Throttle
    clearTimeout(this._throttleTimeout)
    const diffTime = this._lastLogTime ? logObj.date - this._lastLogTime : 0
    this._lastLogTime = logObj.date
    if (diffTime < this._throttle) {
      try {
        const serializedLog = JSON.stringify([logObj.type, logObj.tag, logObj.args])
        const isSameLog = this._lastLogSerialized === serializedLog
        this._lastLogSerialized = serializedLog
        if (isSameLog) {
          this._lastLogCount++
          if (this._lastLogCount > this._throttleMin) {
          // Auto-resolve when throttle is timed out
            this._throttleTimeout = setTimeout(resolveLog, this._throttle)
            return // SPAM!
          }
        }
      } catch (_) {
        // Circular References
      }
    }

    resolveLog(true)
  }

  _log (logObj) {
    for (const reporter of this._reporters) {
      reporter.log(logObj, {
        async: false,
        stdout: this.stdout,
        stderr: this.stderr
      })
    }
  }

  _logAsync (logObj) {
    return Promise.all(
      this._reporters.map(reporter => reporter.log(logObj, {
        async: true,
        stdout: this.stdout,
        stderr: this.stderr
      }))
    )
  }  

}

// Export class
export default ZitiLogger

