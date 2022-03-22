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

export function isPlainObject (obj) {
  return Object.prototype.toString.call(obj) === '[object Object]'
}

export function isLogObj (arg) {
  // Should be plain object
  if (!isPlainObject(arg)) {
    return false
  }

  // Should contains either 'message' or 'args' field
  if (!arg.message && !arg.args) {
    return false
  }

  // Handle non-standard error objects
  if (arg.stack) {
    return false
  }

  return true
}
