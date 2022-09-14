const typescript = require('rollup-plugin-typescript2');
const { babel } = require('@rollup/plugin-babel');
const { nodeResolve: resolve } = require('@rollup/plugin-node-resolve');
const commonjs = require('@rollup/plugin-commonjs');
const { terser } = require('rollup-plugin-terser');
const dts = require('rollup-plugin-flat-dts');
const del = require('rollup-plugin-delete');

const { builtinModules } = require('module');
const { dependencies } = require('./package.json');

module.exports = [
	{
		input: 'src/index.ts',
		output: [
			{
				file: `dist/index.cjs`,
				format: 'cjs',
				preferConst: true,
				plugins: [dts()],
			},
			{
				file: `dist/index.mjs`,
				format: 'esm',
				preferConst: true,
				plugins: [dts()],
			},
		],
		plugins: [
			typescript({ tsconfig: './tsconfig.json' }),
			babel({
				babelHelpers: 'bundled',
				exclude: '**/node_modules/**',
			}),
			resolve(),
			commonjs(),

			/* Optionally uncomment the line below
				 to minify the final bundle: */
			// terser(),
		],
		external: [
			...builtinModules,
			'node:buffer',
			...Object.keys(dependencies),
		],
	},
];
