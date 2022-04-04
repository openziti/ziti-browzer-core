// import {terser} from 'rollup-plugin-terser';
// import replace from '@rollup/plugin-replace';
// import resolve from '@rollup/plugin-node-resolve';
// import typescript from '@rollup/plugin-typescript';
import babel from "rollup-plugin-babel";
import { nodeResolve } from "@rollup/plugin-node-resolve";
import esformatter from 'rollup-plugin-esformatter';
import json from '@rollup/plugin-json';
// import commonjs from '@rollup/plugin-commonjs';



const SRC_DIR   = 'src';
const BUILD_DIR = 'dist';

// import pkg from './package.json'

const input = [`${SRC_DIR}/index.js`];

const name = 'ZitiBrowzerCore';

let plugins = [
  babel({
    exclude: "node_modules/**"
  }),
  json(),
  // commonjs(),
  // typescript({
  //   typescript: require('typescript'),
  //   tsconfig: "tsconfig.json",
  // }),
  // terser(),
];

export default [
  //
  // IIFE
  //
  // {
  //   input,
  //   output: [
  //     {
  //       dir: "dist/iife",
  //       format: "iife",
  //       esModule: false,
  //       name: name,
  //       exports: "named",
  //     },
  //   ],
  //   external: [
  //     ...Object.keys(pkg.dependencies || {}),
  //     ...Object.keys(pkg.peerDependencies || {}),
  //   ],
  //   treeshake: true,
  //   plugins: plugins,
  // },
  //
  // UMD
  //
  // {
  //   input,
  //   output: [
  //     {
  //       dir: "dist/umd",
  //       format: "umd",
  //       esModule: false,
  //       name: name,
  //       exports: "named",
  //     },
  //   ],
  //   external: [
  //     ...Object.keys(pkg.dependencies || {}),
  //     ...Object.keys(pkg.peerDependencies || {}),
  //   ],
  //   treeshake: true,
  //   plugins: plugins,
  // },
  //
  // ESM and CJS
  //
  {
    input,
    plugins: plugins.concat(nodeResolve(), esformatter({indent: { value: '  '}})),
    output: [
      {
        dir: "dist/esm",
        format: "esm",
        exports: "named",
      },
      {
        dir: "dist/cjs",
        format: "cjs",
        exports: "named",
      },
    ],
  },
];
