import { Buffer } from 'node:buffer';

import moment from 'moment';
import { V2 as paseto } from 'paseto';
import * as paserk from './paserk/paserk';

import { api } from './api/signing';
import { ed25519, pemToPubkey } from './encoding';
import {
	getSigningAuthority,
	MessageClaims,
	parseClaims,
	PubKeySource,
} from './auth';

/*
 * @internal
 */
export const verifyRawClaims = (
	replid: string,
	user: string,
	cluster: string,
	claims: MessageClaims,
	anyReplid: boolean,
	anyUser: boolean,
	anyCluster: boolean,
): null => {
	if (claims !== null) {
		if (replid !== '' && !anyReplid) {
			if (!claims.Repls[replid]) {
				throw new Error('not authorized (replid)');
			}
		}

		if (user !== '' && !anyUser) {
			if (!claims.Users[user]) {
				throw new Error('not authorized (user)');
			}
		}

		if (cluster !== '' && !anyCluster) {
			if (!claims.Clusters[cluster]) {
				throw new Error('not authorized (cluster)');
			}
		}
	}

	return null;
};

/**
 * @internal
 */
export const verifyClaims = (
	iat: Date,
	exp: Date,
	replid: string,
	user: string,
	cluster: string,
	claims: MessageClaims,
): null => {
	if (moment(iat).isAfter(moment())) {
		throw new Error(`not valid for ${moment(iat).toNow(true)}`);
	}

	if (moment(exp).isBefore(moment())) {
		throw new Error(`expired ${moment(iat).fromNow(true)} ago`);
	}

	return verifyRawClaims(replid, user, cluster, claims, false, false, false);
};

/**
 * @internal
 */
interface VerifyChainResult {
	verifiedBytes: Buffer;
	cert?: api.GovalCert;
}

// VerifyOption specifies an additional verification step to be performed on an identity.
export class VerifyOption {
	f: (identity: api.GovalReplIdentity) => null;

	constructor(f: (identity: api.GovalReplIdentity) => null) {
		this.f = f;
	}

	verify(identity: api.GovalReplIdentity): null {
		return this.f(identity);
	}
}

// WithVerify allows the caller to specify an arbitrary function to perform
// verification on the identity prior to it being returned.
export const WithVerify = (
	f: (identity: api.GovalReplIdentity) => null,
): VerifyOption => {
	return new VerifyOption(f);
};

// WithSource verifies that the identity's origin replID matches the given
// source, if present. This can be used to enforce specific clients in servers
// when verifying identities.
export const WithSource = (sourceReplid: string): VerifyOption => {
	return WithVerify((identity: api.GovalReplIdentity): null => {
		if (
			identity.originReplid !== '' &&
			identity.originReplid != sourceReplid
		) {
			throw new Error(
				`identity origin replid does not match. expected ${sourceReplid}; got ${identity.originReplid}`,
			);
		}

		return null;
	});
};

/**
 * @internal
 */
class Verifier {
	public claims?: MessageClaims;
	public anyReplid?: boolean;
	public anyUser?: boolean;
	public anyCluster?: boolean;
	
	constructor() {}

	/**
	 * @internal
	 */
	async verifyToken(
		token: string,
		pubkey: ed25519.PublicKey,
	): Promise<Buffer> {
		const bytes = await paseto.verify(token, pubkey, {
			buffer: true,
		});
	
		return bytes;
	}

	/**
	 * @internal
	 */
	async verifyTokenWithKeyID(
		token: string,
		keyid: string,
		issuer: string,
		getPubKey: PubKeySource,
	): Promise<Buffer> {
		const pubkey = getPubKey(keyid, issuer);
		return await this.verifyToken(token, pubkey);
	}

	/**
	 * @internal
	 */
	async verifyTokenWithCert(
		token: string,
		cert: api.GovalCert,
	): Promise<Buffer> {
		let pubkey: ed25519.PublicKey;
	
		if (cert.publicKey.startsWith(paserk.PaserkPublicHeader)) {
			pubkey = paserk.PASERKPublicToPublicKey(cert.publicKey);
		} else {
			pubkey = pemToPubkey(cert.publicKey);
		}
	
		return await this.verifyToken(token, pubkey);
	}

	/**
	 * @internal
	 */
	verifyCert(
		certBytes: Buffer,
		signingCert: api.GovalCert,
	): api.GovalCert {
		const cert = api.GovalCert.deserializeBinary(
			Buffer.from(certBytes.toString('utf8'), 'base64url'),
		);
	
		// Verify that the cert is valid
		verifyClaims(
			new Date(cert.iat.seconds * 1000),
			new Date(cert.exp.seconds * 1000),
			'',
			'',
			'',
			null,
		);
	
		// If the parent cert is not the root cert
		if (signingCert !== undefined) {
			const claims = parseClaims(signingCert);
			if (!claims.Flags[api.FlagClaim.SIGN_INTERMEDIATE_CERT]) {
				throw new Error(
					"signing cert doesn't have authority to sign intermediate certs",
				);
			}
	
			// Verify the cert claims agrees with its signer
			const authorizedClaims: Record<string, Record<string, any>> = {};
	
			let anyReplid: boolean;
			let anyUser: boolean;
			let anyCluster: boolean;
	
			for (const claim of signingCert.claims) {
				authorizedClaims[claim.toString()] = {};
	
				switch (claim.claim) {
					case 'flag': {
						if (claim.flag === api.FlagClaim.ANY_REPLID) {
							anyReplid = true;
						}
						if (claim.flag === api.FlagClaim.ANY_USER) {
							anyUser = true;
						}
						if (claim.flag === api.FlagClaim.ANY_CLUSTER) {
							anyCluster = true;
						}
					}
				}
			}
	
			for (const claim of cert.claims) {
				switch (claim.claim) {
					case 'flag': {
						this.anyReplid = claim.flag === api.FlagClaim.ANY_REPLID;
						this.anyUser = claim.flag === api.FlagClaim.ANY_USER;
						this.anyCluster = claim.flag === api.FlagClaim.ANY_CLUSTER;
					}
					case 'replid': {
						if (anyReplid) continue;
						break;
					}
					case 'user': {
						if (anyUser) continue;
						break;
					}
					case 'cluster': {
						if (anyCluster) continue;
						break;
					}
				}
	
				if (!authorizedClaims[claim.toString()]) {
					throw new Error(
						`signing cert does not authorize claim: ${claim}`,
					);
				}
			}
		}
	
		// Store this cert's claims so we can validate tokens later.
		const certClaims = parseClaims(cert);
		if (certClaims !== null) {
			this.claims = certClaims;
		}
	
		return cert;
	}

	/**
	 * @internal
	 */
	async verifyChain(
		token: string,
		getPubKey: PubKeySource,
	): Promise<VerifyChainResult> {
		const signingAuthority = getSigningAuthority(token);
	
		switch (signingAuthority.cert) {
			case 'key_id': {
				const verifiedBytes = await this.verifyTokenWithKeyID(
					token,
					signingAuthority.key_id,
					signingAuthority.issuer,
					getPubKey,
				);
	
				return { verifiedBytes };
			}
			case 'signed_cert': {
				const { verifiedBytes: signingBytes, cert: skipLevelCert } =
					await this.verifyChain(signingAuthority.signed_cert, getPubKey);
	
				const signingCert = this.verifyCert(signingBytes, skipLevelCert);
	
				const verifiedBytes = await this.verifyTokenWithCert(token, signingCert);
	
				return { verifiedBytes, cert: signingCert };
			}
			default: {
				throw new Error(`unknown token authority ${signingAuthority}`);
			}
		}
	}

	/*
	 * @internal
	 * checkClaimsAgainstToken ensures the claims match up with the token.
	 * This ensures that the final token in the chain is not spoofed via the forwarding protection private key.
	 */
	checkClaimsAgainstToken(
		token: api.GovalReplIdentity,
	): null {
		// if the claims are nil, it means that the token was signed by the root privkey,
		// which implicitly has all claims.
		if (this.claims === null) {
			return null;
		}
	
		return verifyRawClaims(
			token.replid,
			token.user,
			'',
			this.claims,
			this.anyReplid,
			this.anyUser,
			this.anyCluster,
		);
	}
}

/**
 * @internal
 */
export { Verifier };

/*
 * @internal
 */
interface ChainResult {
	verifier: Verifier;
	bytes: Buffer;
	cert: api.GovalCert;
}

/**
 * @internal
 * easy entry-point so you don't need to create a verifier yourself
 */
export const verifyChain = async (token: string, getPubKey: PubKeySource): Promise<ChainResult> => {
	const v = new Verifier();
	const { verifiedBytes: bytes, cert } = await v.verifyChain(token, getPubKey);

	return { verifier: v, bytes, cert };
};

// VerifyIdentity verifies that the given `REPL_IDENTITY` value is in fact
// signed by Goval's chain of authority, and addressed to the provided audience
// (the `REPL_ID` of the recipient).
//
// The optional options allow specifying additional verifications on the identity.
export async function VerifyIdentity(
	message: string,
	audience: string,
	getPubKey: PubKeySource,
	...options: VerifyOption[]
): Promise<api.GovalReplIdentity> {
	const { verifier: v, bytes } = await verifyChain(message, getPubKey);

	const signingAuthority = getSigningAuthority(message);

	let identity: api.GovalReplIdentity;

	switch (signingAuthority.version) {
		case api.TokenVersion.BARE_REPL_TOKEN: {
			throw new Error('wrong type of token provided');
		}
		case api.TokenVersion.TYPE_AWARE_TOKEN: {
			identity = api.GovalReplIdentity.deserializeBinary(Buffer.from(bytes.toString('utf8'), 'base64url'));
		}
	}

	if (audience !== identity.aud) {
		throw new Error(
			`message identity mismatch. expected ${audience}, got ${identity.aud}`,
		);
	}

	v.checkClaimsAgainstToken(identity);

	for (const option of options) {
		option.verify(identity);
	}

	return identity;
}

// VerifyIdentityWithSource verifies that the given `REPL_IDENTITY` value is in fact
// signed by Goval's chain of authority, and addressed to the provided audience
// (the `REPL_ID` of the recipient). It also verifies that the identity's origin replID
// matches the given source, if present. This can be used to enforce specific clients
// in servers when verifying identities.
export async function VerifyIdentityWithSource(message: string, audience: string, sourceReplid: string, getPubKey: PubKeySource): Promise<api.GovalReplIdentity> {
	const identity = await VerifyIdentity(message, audience, getPubKey);
	
	if (identity.originReplid !== '' && identity.originReplid !== sourceReplid) {
		throw new Error(`identity origin replid does not match. expected ${sourceReplid}; got ${identity.originReplid}`)
	}

	return identity;
};