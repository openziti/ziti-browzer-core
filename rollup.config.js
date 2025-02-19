// import {terser} from 'rollup-plugin-terser';
// import replace from '@rollup/plugin-replace';
import babel from "rollup-plugin-babel";
import { nodeResolve } from "@rollup/plugin-node-resolve";
// import esformatter from 'rollup-plugin-esformatter';
import json from '@rollup/plugin-json';
import commonjs from '@rollup/plugin-commonjs';
import nodePolyfills from 'rollup-plugin-polyfill-node';



const SRC_DIR   = 'src';

const input = [`${SRC_DIR}/index.js`];

const name = 'ZitiBrowzerCore';

// let plugins = [
//   babel({
//     exclude: "node_modules/**"
//   }),
//   commonjs(),
//   json(),
//   nodeResolve({preferBuiltins: false, browser: true}),
//   nodePolyfills(),
//   esformatter({indent: { value: '  '}}),
//   // terser(),
// ];
let plugins = [
  commonjs(
    {
      dynamicRequireTargets: [
        // include using a glob pattern (either a string or an array of strings)
        // 'node_modules/readable-stream/*.js',
    
        // exclude files that are known to not be required dynamically, this allows for better optimizations
        // '!node_modules/logform/index.js',
        // '!node_modules/logform/format.js',
        // '!node_modules/logform/levels.js',
        // '!node_modules/logform/browser.js'
      ]
    }
  ),
  babel({
    exclude: "node_modules/**"
  }),
  json(),
  nodeResolve({preferBuiltins: false, browser: true}),
  nodePolyfills(),
  // esformatter({indent: { value: '  '}}),
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
    treeshake: true,
    // plugins: plugins.concat(nodeResolve({preferBuiltins: false, browser: true}), esformatter({indent: { value: '  '}})),
    plugins: plugins,
    output: [
      {
        dir: "dist/esm",
        format: "esm",
        exports: "named",
      },
      // {
      //   dir: "dist/cjs",
      //   format: "cjs",
      //   exports: "named",
      // },
    ],
  },
];
