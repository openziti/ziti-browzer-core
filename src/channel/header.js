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
import { defaultOptions } from './header-options'
import { isEqual, isNull } from 'lodash-es';
import { toUTF8Array } from '../utils/utils';
import throwIf from '../utils/throwif';
import { ZitiEdgeProtocol } from '../channel/protocol';
import { Buffer } from 'buffer';


/**
 *    Header
 */
 class Header {

  /**
   * 
   */
  constructor(headerId, options) {
    this._headerId = headerId;
    this._options = flatOptions(options, defaultOptions);

    throwIf(isNull(this._options.headerType), 'headerType not specified');
    this._headerType = this._options.headerType;

    throwIf(isNull(this._options.headerData), 'headerData not specified');
    this._headerData = this._options.headerData;
    console.log('this._headerData is: ', this._headerData);

    this._bytesForWire = this._createBytesForWire();

    this._length = this._bytesForWire.length;
  }

  getId() {
    return this._headerId;
  }

  getData() {
    return this._headerData;
  }

  getLength() {
    return this._length;
  }

  getBytesForWire() {
    return this._bytesForWire;
  }

  _createBytesForWire() {

    if (isEqual(this._headerType, ZitiEdgeProtocol.header_type.StringType)) {

      let headerDataLength = Buffer.byteLength(this._headerData, 'utf8');

      let bytes_header_id_and_length = new Buffer( 4 + 4 );
      bytes_header_id_and_length.writeUInt32LE(this._headerId, 0);
      bytes_header_id_and_length.writeUInt32LE(headerDataLength, 4);


      let bytes_header_data = toUTF8Array(this._headerData);
      let buffer_header_data = Buffer.from(bytes_header_data);

      let bytes_complete_header = Buffer.concat([bytes_header_id_and_length, buffer_header_data], 4 + 4 + headerDataLength );

      return bytes_complete_header;

    } else if (isEqual(this._headerType, ZitiEdgeProtocol.header_type.IntType)) {

      let headerDataLength = 4;

      let bytes_complete_header = new Buffer( 4 + 4 + 4 );
      bytes_complete_header.writeUInt32LE(this._headerId, 0);
      bytes_complete_header.writeUInt32LE(headerDataLength, 4);
      bytes_complete_header.writeInt32LE(this._headerData, 8);

      return bytes_complete_header;

    } else if (isEqual(this._headerType, ZitiEdgeProtocol.header_type.Uint8ArrayType)) {

      let headerDataLength = Buffer.byteLength(this._headerData, 'utf8');

      let bytes_header_id_and_length = new Buffer( 4 + 4 );
      bytes_header_id_and_length.writeUInt32LE(this._headerId, 0);
      bytes_header_id_and_length.writeUInt32LE(headerDataLength, 4);

      let buffer_header_data = Buffer.from(this._headerData);

      let bytes_complete_header = Buffer.concat([bytes_header_id_and_length, buffer_header_data], 4 + 4 + headerDataLength );

      return bytes_complete_header;

    } else {

      throw new Error('unknown headerType');

    }
  }

  _createFromBytesFromWire(bytes) {
  }

}

// Export class
export {
  Header
}
