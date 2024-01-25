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

import { ClientRequest } from './_http_client';
import { HTTPParser } from './http-parser';
const methods = HTTPParser.methods;

import { IncomingMessage } from './_http_incoming';
import {
  validateHeaderName,
  validateHeaderValue,
  OutgoingMessage
} from './_http_outgoing';

function request(url, options, cb) {
  return new ClientRequest(url, options, cb);
}

function get(url, options, cb) {
  const req = request(url, options, cb);
  req.end();
  return req;
}

const http = {
  METHODS: methods.slice().sort(),
  ClientRequest,
  IncomingMessage,
  OutgoingMessage,
  validateHeaderName,
  validateHeaderValue,
  get,
  request
};

export {
  http
};