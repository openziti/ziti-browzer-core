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

'use strict';


function uncurryThis(func) {
  return function () {
    return Function.call.apply(func, arguments);
  }
}


const TypedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);

const TypedArrayProto_toStringTag =
    uncurryThis(
      Object.getOwnPropertyDescriptor(TypedArrayPrototype,
                                     Symbol.toStringTag).get);

function isTypedArray(value) {
  return TypedArrayProto_toStringTag(value) !== undefined;
}

function isUint8Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Uint8Array';
}

function isUint8ClampedArray(value) {
  return TypedArrayProto_toStringTag(value) === 'Uint8ClampedArray';
}

function isUint16Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Uint16Array';
}

function isUint32Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Uint32Array';
}

function isInt8Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Int8Array';
}

function isInt16Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Int16Array';
}

function isInt32Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Int32Array';
}

function isFloat32Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Float32Array';
}

function isFloat64Array(value) {
  return TypedArrayProto_toStringTag(value) === 'Float64Array';
}

function isBigInt64Array(value) {
  return TypedArrayProto_toStringTag(value) === 'BigInt64Array';
}

function isBigUint64Array(value) {
  return TypedArrayProto_toStringTag(value) === 'BigUint64Array';
}

const TYPES = {
  // ...internalBinding('types'),
  isArrayBufferView: ArrayBuffer.isView,
  isTypedArray,
  isUint8Array,
  isUint8ClampedArray,
  isUint16Array,
  isUint32Array,
  isInt8Array,
  isInt16Array,
  isInt32Array,
  isFloat32Array,
  isFloat64Array,
  isBigInt64Array,
  isBigUint64Array
};

export {
  TYPES
}