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

import gulp from 'gulp';
import del from 'del';
import fse from 'fs-extra';
import upath from 'upath';
import {execa} from 'execa';
import globby from 'globby';


async function cleanSequence() {
  // Delete generated files from the the TypeScript transpile.
  await del([
    `./dist/esm/*.+(d.ts)`,
  ]);
  // Delete tsc artifacts (if present).
  await del(upath.join('.', 'tsconfig.tsbuildinfo'));
}


/**
 * Transpiles all files listed in the root tsconfig.json's 'include' section
 * into .js and .d.ts files. Creates stub .mjs files that re-export the contents
 * of the .js files.
 */
 async function transpile_typescript() {
  await execa('tsc', ['--build', 'tsconfig.json'], {preferLocal: true});

  const jsFiles = await globby(`dist/esm/*.js`, {
    ignore: ['**/build/**'],
  });
}


gulp.task("build", async function () {

  await transpile_typescript();

});

gulp.task("clean", async function () {

  await cleanSequence();

});
