import babel from "rollup-plugin-babel";
import { nodeResolve } from "@rollup/plugin-node-resolve";
import json from '@rollup/plugin-json';
import commonjs from '@rollup/plugin-commonjs';
import nodePolyfills from 'rollup-plugin-polyfill-node';
import dts from 'rollup-plugin-dts';

const SRC_DIR = 'src';

// Include both JS and TS files
const input = [`${SRC_DIR}/index.js`];

const plugins = [
  commonjs(),
  babel({ exclude: "node_modules/**" }),
  json(),
  nodeResolve({ preferBuiltins: false, browser: true }),
  nodePolyfills(),
  // typescript({ tsconfig: './tsconfig.json' }), // Move TypeScript here
];

// Clean `dist/esm` before building

export default [
  {
    input,
    // plugins: [cleanPlugin, ...plugins],
    plugins: [...plugins],
    output: [
      {
        dir: "dist/esm",
        format: "esm",
        exports: "named",
        sourcemap: true,
      },
    ],
  },
  // Generate TypeScript declaration files
  {
    input,
    output: {
      file: 'dist/esm/index.d.ts',
      format: 'es'
    },
    plugins: [dts()]
  }
  
  // // Generate TypeScript declaration files
  // {
  //   input: `${SRC_DIR}/index.ts`,
  //   output: { file: 'dist/esm/index.d.ts', format: 'es' },
  //   plugins: [dts()],
  // }
];
