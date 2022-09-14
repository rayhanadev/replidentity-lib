import * as replidentity from '../dist/index.mjs';

async function main() {
	// To prevent security problems, every time we prove our identity
	// to another Repl, it needs to be addressed to it, so that the
	// other Repl cannot grab that identity token and spoof you.
	// In order to do that, we need to get that other Repl's `$REPL_ID`.
	let audience = 'another-cool-repl-id';

	const identityToken = await replidentity.CreateIdentityTokenAddressedTo(audience);

	// The other Repl can now be sent the identityToken and can verify
	// the authenticity of it!
	// In this case, we'll just immediately verify it for demo purposes.

	// audience = process.env.REPL_ID // uncomment this on the other Repl.
	const replIdentity = await replidentity.VerifyIdentity(
		identityToken,
		audience,
		replidentity.ReadPublicKeyFromEnv,
	);

	console.log(`The identity token (${identityToken.length} bytes) is:\n`);
	console.log(
`  repl id:     ${replIdentity.replid}
     user:     ${replIdentity.user}
     slug:     ${replIdentity.slug}
 audience:     ${replIdentity.aud}
ephemeral:     ${replIdentity.ephemeral}
   origin:     ${replIdentity.originReplid}`);
}

main();