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

import EventEmitter from 'events';
import { isUndefined } from 'lodash-es';
import { Buffer } from 'buffer';

var zitiSocketCounter = 0;

class ZitiSocket extends EventEmitter {

    constructor(opts) {
        super();

        /**
         * 
         */
        this.isWebSocket = false;
        if (typeof opts !== 'undefined') {
            if (typeof opts.isWebSocket !== 'undefined') {
                this.isWebSocket = opts.isWebSocket;
            }
        }

        /**
         * This stream is where we'll put any data returned from a Ziti connection (see ziti_dial.data.call_back)
         */
        this.readableZitiStream = new ReadableStream({
            start(controller) {
                self.readableZitiStreamController = controller;
            }
        });

        /**
         * The underlying Ziti Context
         * @private
         * @type {string}
         */
        this.zitiContext = opts.zitiContext;

        /**
         * The active HTTP request
         */
        this.req = opts.req;

        /**
         * The underlying Ziti Connection
         * @private
         * @type {string}
         */
        this.zitiConnection;


        /**
         * 
         */
        this._writable = false;

        /**
         * 
         */
        this._id = zitiSocketCounter++; // debugging
    }




    /**
     * Make a connection to the specified Ziti 'service'.  We do this by invoking the ziti_dial() function in the Ziti NodeJS-SDK.
     * @param {*} service 
     */
    ziti_dial(service) {
        
        const self = this;
        return new Promise((resolve) => {
            if (self.zitiConnection) {
                resolve(self.zitiConnection);
            }
            else {
                window.ziti.ziti_dial(
                    service,

                    self.isWebSocket,

                    /**
                     * on_connect callback.
                     */
                    (conn) => {
                        // logger.info('on_connect callback: conn: %s', this.connAsHex(conn))
                        resolve(conn);
                    },

                    /**
                     * on_data callback
                     */
                    (data) => {
                        conn.zitiContext.logger.trace('on_data callback: conn: %s, data: \n%s', this.connAsHex(this.zitiConnection), data.toString());
                        this.readableZitiStreamController.enqueue(data);
                    },
                );
            }
        });
    }

    /**
     * Write data onto the underlying Ziti connection by invoking the ziti_write() function in the Ziti NodeJS-SDK.  The
     * NodeJS-SDK expects incoming data to be of type Buffer.
    */
    ziti_write(conn, buffer) {
        return new Promise((resolve) => {
            window.ziti.ziti_write(
                conn, buffer,
                () => {
                    resolve();
                },
            );
        });
    }

    /**
     * 
     */
    captureResponseData(conn, data) {

        conn.zitiContext.logger.trace(`ZitiSocket.captureResponseData() <- conn[${conn.id}] socket[${conn.socket._id}][${conn.socket.isNew}] dataLen: [${data.byteLength}]`);
        // conn.zitiContext.logger.trace(`ZitiSocket.captureResponseData() <- conn[${conn.id}] (string)data: [${Buffer.from(data, 'utf8')}]`);

        let zitiSocket = conn.socket;

        // If we have an innerTLSsocket, then we need to pass it the data 
        // so it can be decrypted according to the handshake that was done with
        // the connected service (i.e. web server listening on TLS)
        if (!isUndefined(zitiSocket.innerTLSSocket)) {
            // zitiSocket.innerTLSSocket.captureResponseData(conn, data);
            zitiSocket.innerTLSSocket.process(data);
        } else {
            if (data.byteLength > 0) {
                zitiSocket.emit('data', data);
            } else {
                conn.zitiContext.logger.trace(`ZitiSocket.captureResponseData() <- conn[${conn.id}] emitting 'close' event`);
                zitiSocket.emit('close', data);
            }
        }
    }

    /**
     * Connect to a Ziti service.
    */
    async connect(opts) {
        
        if (opts.isNew) {

            if (typeof opts.conn == 'object') {
                this.zitiConnection = opts.conn;
            }
            else if (typeof opts.serviceName == 'string') {
                this.zitiConnection = this.zitiContext.newConnection(opts);
                this.zitiConnection.socket = this;
                this.zitiContext.logger.debug(`ZitiSocket.connect() dial[${opts.serviceName}] socket[${this._id}] conn[${this.zitiConnection.id}] initiated`);
                await this.zitiContext.dial(this.zitiConnection, opts.serviceName);
                this.zitiContext.logger.debug(`ZitiSocket.connect() dial[${opts.serviceName}] socket[${this._id}] conn[${this.zitiConnection.id}] now complete`);
            } else {
                throw new Error('no serviceName or conn was provided');
            }

        } else {

            //
            // Yes, this code is redundant with that above... but this will change once reusable socket connections is working
            //
            this.zitiConnection = this.zitiContext.newConnection(opts);
            this.zitiConnection.socket = this;
            this.zitiContext.logger.debug(`ZitiSocket.connect() dial[${opts.serviceName}] socket[${this._id}] conn[${this.zitiConnection.id}] initiated`);
            await this.zitiContext.dial(this.zitiConnection, opts.serviceName);
            this.zitiContext.logger.debug(`ZitiSocket.connect() dial[${opts.serviceName}] socket[${this._id}] conn[${this.zitiConnection.id}] now complete`);
        }

        this._writable = true;

        // Prepare to capture response data from the request we are about to launch
        this.zitiConnection.dataCallback = (this.captureResponseData);
        this.zitiConnection.socket = (this);

        // Let the HTTP parser layer know we are ready/available
        this.emit('connect', this.zitiConnection);
    }
     

    /**
     * 
     */
    _read() { /* NOP */ }
    read()  { /* NOP */ }


    /**
     * 
     */
    destroy() { /* NOP */ }


    /**
     * Returns a Promise that will resolve _only_ after a Ziti connection has been established for this instance of ZitiSocket.
     */
    getZitiConnection() {
        const self = this;
        return new Promise((resolve) => {
            (function waitForConnected() {
                if (self.zitiConnection && (!isUndefined(self.zitiConnection.channel))) return resolve(self.zitiConnection);
                setTimeout(waitForConnected, 10);
            })();
        });
    }

    connAsHex(conn) {
        if (conn < 0) {
            conn = 0xFFFFFFFF + conn + 1;
        }
        return '0x' + conn.toString(16);
    }

    /**
     * Implements the writeable stream method `_write` by pushing the data onto the underlying Ziti connection.
     * It is possible that this function is called before the Ziti connect has completed, so this function will (currently)
     * await Ziti connection establishment (as opposed to buffering the data).
    */
    async write(chunk, encoding, cb) {

        let buffer;

        if (typeof chunk === 'string' || chunk instanceof String) {
            buffer = Buffer.from(chunk, 'utf8');
        } else if (Buffer.isBuffer(chunk)) {
            buffer = chunk;
        } else if (chunk instanceof Uint8Array) {
            buffer = Buffer.from(chunk, 'utf8');
        } else {
            throw new Error('chunk type of [' + typeof chunk + '] is not a supported type');
        }
        if (buffer.length > 0) {

            const conn = await this.getZitiConnection().catch((e) => conn.zitiContext.logger.error('inside ziti-socket.js _write(), Error: ', e.message));

            // If we have an innerTLSsocket, then we need to pass it the chunk 
            // so it can be encrypted according to the handshake that was done with
            // the connected service (i.e. web server listening on TLS)
            if (!isUndefined(this.innerTLSSocket)) {
                this.innerTLSSocket.write(conn, buffer);
            } else {
                conn.channel.write(conn, buffer);
            }

        }
        if (cb) {
            cb();
        }
    }

    /**
     *
     */
    cork() {
        this._writable = false;
    }
    uncork() {
        this._writable = true;
    }

    /**
     *
     */
    pause() {
        this._writable = false;
    }
    resume() {
        this._writable = true;
    }

    /**
     *
     */
    async destroy() {
        this._writable = false;
        await this.zitiContext.close(this.zitiConnection);
    }
    
    /**
     *
     */
    async end(data, encoding, callback) {
        this._writable = false;
        await this.zitiContext.close(this.zitiConnection);
    }

    /**
     * Implements the writeable stream method `_final` used when .end() is called to write the final data to the stream.
     */
    _final(cb) {
        cb();
    }

    /**
     *
     */
    setTimeout() {
        /* NOP */
    }

    /**
     *
     */
    setNoDelay() {
        /* NOP */
    }

    /**
     *
     */
    unshift(head) {
        /* NOP */
    }
    
}

Object.defineProperty(ZitiSocket.prototype, 'writable', {
    get() {
      return (
        this._writable
      );
    }
});


export {
    ZitiSocket
};