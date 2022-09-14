![](https://edge.furret.codes/f/nodejs-package-template-preview.png)

# NodeJS Package Template on Replit

This is the best, fastest scaffolding to getting started on your next NodeJS package on
Replit! Quickly write your code in Typescript or Javascript using the latest NodeJS
version (NodeJS v18.2.0), build and bundle your code with bundlers, and
test your code in multiple environments with Jest. **No setup required!**

## Development

You can write your package using Typescript or ESM, visit the [/src](#src) and start
scripting.

You can install packages with Yarn.

```shell
$ yarn add [package]
```

### More Resources

-   [Creating Node.js modules](https://docs.npmjs.com/creating-node-js-modules#create-a-package-json-file)
-   [How To Create a Node.js Module](https://www.digitalocean.com/community/tutorials/how-to-create-a-node-js-module)
-   [How to make a beautiful, tiny npm package and publish it](https://www.freecodecamp.org/news/how-to-make-a-beautiful-tiny-npm-package-and-publish-it-2881d4307f78/)

---

## Tooling

There are also several utility scripts to help make your code neater and check for
errors.

### Linting

This template uses a [preconfigured ESLint](#eslint.config.json) linter to scan for
code errors. You can easily run ESLint via:

```shell
$ yarn lint # to check for errors
$ yarn lint:fix # to fix fixable errors
```

### Formatting

This template uses a [preconfigured Prettier](#prettier.config.json) formatter to scan
for style issues. You can easily run Prettier via:

```shell
$ yarn format # to check for style issues
$ yarn format:fix # to fix style issues
```

---

## Building

To build your code, this template uses the [Rollup bundler](https://rollupjs.org/guide/en/)
and a [preconfigured build file](#rollup.config.cjs) which also utilizes the build
Babel environment specified in the [Babel config file](#babel.config.json). You can
build your package via:

```shell
$ yarn build
```

This will generate a CommonJS output, an ESM output, and a type declaration file (if
you're using Typescript) in the [/dist](#dist/) folder. The `package.json` file has
already been configured to export these files for your convinence.

### More Information

-   [Rollup Plugins](https://github.com/rollup/awesome)

---

## Testing

This template uses Jest to run unit tests on each of the build files. To run all tests
click the run button or run:

```shell
$ yarn test
```

You can run specific tests as well:

```shell
$ yarn test:common # /tests/common.test.js
$ yarn test:esm # /tests/esm.test.js
$ yarn test:ts # /tests/typescript.test.js
```

All files are transpiled to run in specified environment found in the test Babel
environment in the [Babel config file](#babel.config.json). This means you can write
CommonJS and ESM files ending in `.js` and Jest will find and test them. Jest will also
test Typescript files ending in `.ts` so you can write tests in Typescript as well.

### More Information

-   [Jest Getting Started](https://jestjs.io/docs/getting-started)

---

## Community

This template has a preconfigured `package.json` which you can fill out with details
about Github repositories, main websites and more. It also has [Licensing](#LICENSE)
(MIT License by default), [Code of Conduct](#CODE_OF_CONDUCT.md), and
[Contributing](#CONTRIBUTING.md) information so you can easily push to your code to
the open source community.

### More Information

-   [package.json Docs](https://docs.npmjs.com/cli/v8/configuring-npm/package-json)
-   [Choose a License](https://choosealicense.com/)
