# Repl Identity

(for Typescript/Javascript!)

From [go-replidentity](https://github.com/replit/go-replidentity)

> Repl Identity stores a REPL_IDENTITY token in every Repl automatically. This token is a signed PASETO that includes verifiable repl identity data (such as the user in the repl, and the repl ID).
> 
> **WARNING: in their current form, these tokens are very forwardable! You should only send these tokens to repls that you trust, or between repls that you own.**
> 
> This package provides the necessary code to verify these tokens.
> 
> Check the example at tests/identity.test.js for an example usage. You can also see this in action at https://replit.com/@RayhanADev/replidentity-lib. If you are logged in to Replit, you'll see your username when you click "Run" on the Cover Page - that's Repl Identity at work.

## Install

```sh
# with NPM
$ npm install replidentity

# with Yarn
$ yarn add replidentity
```

## Usage

```js
import * as replidentity from 'replidentity';

async function main() {
	let audience = 'another-cool-repl-id';
	const identityToken = await replidentity.CreateIdentityTokenAddressedTo(audience);

	const parsedIdentity = await replidentity.VerifyIdentity(
		identityToken,
		audience,
		replidentity.ReadPublicKeyFromEnv,
	);

	console.log(`The identity token (${identityToken.length} bytes) is:`);
	console.log(`
  repl id:  ${parsedIdentity.replid}
     user:  ${parsedIdentity.user}
     slug:  ${parsedIdentity.slug}
 audience:  ${parsedIdentity.aud}
ephemeral:  ${parsedIdentity.ephemeral}
   origin:  ${parsedIdentity.originReplid}`);
}

main();
```

For more information, visit [the blog post](https://blog.replit.com/repl-identity)!