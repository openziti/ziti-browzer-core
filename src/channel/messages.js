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


import { isNull, isUndefined } from 'lodash-es';
let nativePromise = null;


/**
 *    Messages
 */
 class Messages {

  /**
   * 
   */
  constructor(options) {
    this._items = new Map();
    this._zitiContext = options.zitiContext;
    this._conn = options.conn;
    this._channel = options.channel;
  }

  /**
   * Creates new message and stores it in the list.
   *
   * @param {String|Number} messageId
   * @param {Function} fn
   * @param {Number} timeout
   * @returns {Promise}
   */
  create(conn, messageId, fn, timeout) {
    this._rejectExistingMessage(messageId);
    return this._createNewMessage(conn, messageId, fn, timeout);
  }

  resolve(conn, data) {
    if (!isNull(conn) && this._items.has(conn)) {
      this._items.get(conn).resolve(data);
    }
  }

  rejectAll(error) {
    this._items.forEach(message => message.isPending ? message.reject(error) : null);
  }

  _rejectExistingMessage(messageId) {
    const existingMessage = this._items.get(messageId);
    if (existingMessage && existingMessage .isPending) {
      existingMessage .reject(new Error(`message is replaced, messageId: ${messageId}`));
    }
  }

  _getNativePromise() {

    if (!isNull(nativePromise)) {
      return nativePromise;
    }

    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
      try {
        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        nativePromise = iframe.contentWindow.Promise;
        document.body.removeChild(iframe);
        return nativePromise;
      } catch (err) {
        console.warn('Iframe failed, falling back to global Promise');
      }
    }

    if (typeof globalThis !== 'undefined') {
      nativePromise = globalThis.Promise;
      return nativePromise;
    }

    throw new Error('Unable to locate native Promise in this environment.');
    
  }
  
  _createNewMessage(conn, messageId, fn, timeout) {
    let resolveFn, rejectFn;
  
    if (isUndefined(conn)) {
      conn = -1;  // during edge protocol 'hello' operations, we do not have a connection id yet
    }

    // const timeoutReason = `message was rejected by timeout (${timeout} ms). messageId: ${messageId}`;
  
    let np = this._getNativePromise();

    const message = new np((resolve, reject) => {
      resolveFn = resolve;
      rejectFn = reject;
    });
  
    // Optional: wrap to expose cancellation/reject externally
    const messageWrapper = {
      promise: message,
      resolve: resolveFn,
      reject: rejectFn,
      timeoutHandle: null
    };
  
    // Set timeout to reject if not resolved in time
    // messageWrapper.timeoutHandle = setTimeout(() => {
    //   rejectFn(new Error(timeoutReason));
    //   this._items.delete(messageId);
    // }, timeout);
  
    // Store in map
    this._items.set(conn, messageWrapper);
  
    // Execute the function, passing in resolve/reject if needed
    // If `fn` is meant to use them directly:
    try {
      fn(resolveFn, rejectFn);
    } catch (err) {
      rejectFn(err);
    }
    
    return message;
  }
  

  _deleteMessage (messageId, message) {
    // this check is important when message was replaced
    if (this._items.get(messageId) === message) {
      this._items.delete(messageId);
    }
  }
};

// Export class
export {
  Messages
}
