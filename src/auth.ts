import { Buffer } from 'node:buffer';

import { api } from './api/signing';
import type { ed25519 } from './encoding';

// PubKeySource provides an interface for looking up an [ed25519.PublicKey] from some external source.
export type PubKeySource = (keyid, issuer: string) => ed25519.PublicKey;

/**
 * MessageClaims is a collection of indexable claims that are made by a certificate.
 */
export interface MessageClaims {
	Repls: Record<string, Record<string, any>>;
	Users: Record<string, Record<string, any>>;
	Clusters: Record<string, Record<string, any>>;
	Flags: Record<string, Record<string, any>>;
}

/**
 * @internal
 */
export const parseClaims = (cert: api.GovalCert): MessageClaims => {
	if (cert === undefined) return null;

	const claims: MessageClaims = {
		Repls: {},
		Users: {},
		Clusters: {},
		Flags: {},
	};

	for (const claim of cert.claims) {
		switch (claim.claim) {
			case 'replid': {
				claims.Repls[claim.replid] = {};
				break;
			}

			case 'user': {
				claims.Users[claim.user] = {};
				break;
			}

			case 'cluster': {
				claims.Users[claim.cluster] = {};
				break;
			}

			case 'flag': {
				claims.Flags[claim.flag] = {};
			}
		}
	}

	return claims;
};

/**
 * @internal
 */
export const getSigningAuthority = (
	message: string,
): api.GovalSigningAuthority => {
	const footerBytes = Buffer.from(
		Buffer.from(message.split('.')[3], 'base64url').toString('utf8'),
		'base64url',
	);

	const signingAuthority =
		api.GovalSigningAuthority.deserializeBinary(footerBytes);
	return signingAuthority;
};
