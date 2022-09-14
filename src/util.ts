import { Buffer } from 'node:buffer';
import { ed25519 } from './encoding';
import { NewSigningAuthority } from './sign';

// ReadPublicKeyFromEnv provides a [PubKeySource] that reads public keys from the `REPL_PUBKEYS`
// environment variable that is present in all repls.
export const ReadPublicKeyFromEnv = (
	keyid: string,
	issuer: string,
): ed25519.PublicKey => {
	const pubkeys = JSON.parse(process.env.REPL_PUBKEYS);
	const pubkey = pubkeys[keyid];

	if (!pubkey) return null;

	const keyBytes = Buffer.from(pubkey, 'base64url');
	return keyBytes;
};

export const CreateIdentityTokenSigningAuthority =
	async (): Promise<NewSigningAuthority> => {
		if (process.env.REPL_OWNER === 'five-nine') {
			throw new Error('not logged into Replit, no identity present');
		}

		const identitySigningAuthorityToken = process.env.REPL_IDENTITY;

		if (identitySigningAuthorityToken === '') {
			throw new Error('no REPL_IDENTITY env var present');
		}

		const identitySigningAuthorityKey = process.env.REPL_IDENTITY_KEY;

		if (identitySigningAuthorityKey === '') {
			throw new Error('no REPL_IDENTITY_KEY env var present');
		}
		
		return await new NewSigningAuthority(
			identitySigningAuthorityKey,
			identitySigningAuthorityToken,
			process.env.REPL_ID,
			ReadPublicKeyFromEnv,
		).init();
	};

// CreateIdentityTokenAddressedTo returns a Replit identity token that proves this Repl's identity
// that includes an audience claim to restrict forwarding. It creates a new signing authority each
// time, which can be slow. If you plan on signing multiple tokens, use
// CreateIdentityTokenSigningAuthority() to create an authority to sign with.
export const CreateIdentityTokenAddressedTo = async (
	audience: string,
): Promise<string> => {
	const signingAuthority = await CreateIdentityTokenSigningAuthority();

	if (signingAuthority === null) {
		throw new Error('no signing authority could be created');
	}

	const identityToken = signingAuthority.Sign(audience);

	return identityToken;
};
