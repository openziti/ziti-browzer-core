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

import { LogLevel } from './logLevels.js'

export default {
  // Silent
  silent: {
    level: -1
  },
  // Level 0
  fatal: {
    level: LogLevel.Fatal
  },
  error: {
    level: LogLevel.Error
  },
  // Level 1
  warn: {
    level: LogLevel.Warn
  },
  // Level 2
  log: {
    level: LogLevel.Log
  },
  // Level 3
  info: {
    level: LogLevel.Info
  },
  success: {
    level: LogLevel.Success
  },
  // Level 4
  debug: {
    level: LogLevel.Debug
  },
  // Level 5
  trace: {
    level: LogLevel.Trace
  },
  // Verbose
  verbose: {
    level: LogLevel.Trace
  },

  // Legacy
  ready: {
    level: LogLevel.Info
  },
  start: {
    level: LogLevel.Info
  }
}
