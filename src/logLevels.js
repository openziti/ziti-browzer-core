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

export const LogLevel = {}
LogLevel[LogLevel.Fatal = 0] = 'Fatal'
LogLevel[LogLevel.Error = 0] = 'Error'
LogLevel[LogLevel.Warn = 1] = 'Warn'
LogLevel[LogLevel.Log = 2] = 'Log'
LogLevel[LogLevel.Info = 3] = 'Info'
LogLevel[LogLevel.Success = 3] = 'Success'
LogLevel[LogLevel.Debug = 4] = 'Debug'
LogLevel[LogLevel.Trace = 5] = 'Trace'
LogLevel[LogLevel.Silent = -Infinity] = 'Silent'
LogLevel[LogLevel.Verbose = Infinity] = 'Verbose'

export function normalizeLogLevel (input, types = {}, defaultLevel = 3) {
  if (input == null) { return defaultLevel }
  if (typeof input === 'number') { return input }
  input = input.toLowerCase();
  if (types[input] && types[input].level != null) { return types[input].level }
  return defaultLevel
}
