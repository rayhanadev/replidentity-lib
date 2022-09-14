import { V2 as paseto } from 'paseto';

import * as paserk from './paserk/paserk';
import { api } from './api/signing';
import { getSigningAuthority } from './auth';
import type { PubKeySource } from './auth';
import { verifyChain } from './verify';
import { ed25519 } from './encoding';

// SigningAuthority can generate tokens that prove the identity of one repl
// (your own) against another repl (the audience). Use this to prevent the
// target repl from spoofing your own identity by forwarding the token.
export interface SigningAuthority {
	privateKey: ed25519.PrivateKey;
	signingAuthority: api.GovalSigningAuthority;
	identity: api.GovalReplIdentity;
}

/**
 * @internal
 */
export const signIdentity = async (
	parentPrivateKey: ed25519.PrivateKey,
	parentAuthority: api.GovalSigningAuthority,
	identity: api.GovalReplIdentity,
): Promise<string> => {
	const encodedIdentity = identity.serialize();

	const serializedCert = parentAuthority.serialize();

	return await paseto.sign(
		Buffer.from(Buffer.from(encodedIdentity).toString('base64url')),
		Buffer.from(parentPrivateKey.toString('utf8'), 'base64url'),
		{
			footer: Buffer.from(serializedCert).toString('base64url'),
		},
	);
};

// NewSigningAuthority returns a new SigningAuthority given the marshaled
// private key (obtained from the `REPL_IDENTITY_KEY` environment variable),
// the identity token (obtained from the `REPL_IDENTITY` environment variable),
// the current Repl ID (obtained from the `REPL_ID` environment varaible), and
// the source of public keys (typically [ReadPublicKeyFromEnv]).
class NewSigningAuthority {
	public rawPrivateKey: string;
	public rawIdentity: string;
	public replid: string;
	public getPubKey: PubKeySource;
	public SigningAuthority?: SigningAuthority;

	constructor(
		rawPrivateKey: string,
		rawIdentity: string,
		replid: string,
		getPubKey: PubKeySource,
	) {
		this.rawPrivateKey = rawPrivateKey;
		this.rawIdentity = rawIdentity;
		this.replid = replid;
		this.getPubKey = getPubKey;
	};

	async init(): Promise<this> {
		const { verifier: v, bytes } = await verifyChain(this.rawIdentity, this.getPubKey);
		
		const signingAuthority = getSigningAuthority(this.rawIdentity);
		
		const privateKey = paserk.PASERKSecretToPrivateKey(this.rawPrivateKey);

		let identity: api.GovalReplIdentity;
	
		switch (signingAuthority.version) {
			case api.TokenVersion.BARE_REPL_TOKEN: {
				throw new Error('wrong type of token provided');
			}
			case api.TokenVersion.TYPE_AWARE_TOKEN: {
				identity = api.GovalReplIdentity.deserializeBinary(
					Buffer.from(bytes.toString('utf8'), 'base64url'),
				);
			}
		}
		
		v.checkClaimsAgainstToken(identity);
	
		if (this.replid !== identity.replid) {
			throw new Error(
				`message replid mismatch. expected ${this.replid}, got ${identity.replid}`,
			);
		}
	
		if (this.replid !== identity.aud) {
			throw new Error(
				`message audience mismatch. expected ${this.replid}, got ${identity.aud}`,
			);
		}
	
		const SigningAuthority = {
			privateKey: privateKey,
			signingAuthority: signingAuthority,
			identity: identity,
		};
	
		this.SigningAuthority = SigningAuthority;
		
		return this;
	}

	/**
	 * Sign generates a new token that can be given to the provided audience, and
	 * is resistant against forwarding, so that the recipient cannot forward this
	 * token to another repl and claim it came directly from you.
	 */
	async Sign(
		audience: string,
	): Promise<string> {
		const replIdentity = {
			replid: this.SigningAuthority.identity.replid,
			user: this.SigningAuthority.identity.user,
			slug: this.SigningAuthority.identity.slug,
			aud: audience,
			originReplid: this.SigningAuthority.identity.originReplid,
		};
	
		const token = await signIdentity(
			this.SigningAuthority.privateKey,
			this.SigningAuthority.signingAuthority,
			api.GovalReplIdentity.fromObject(replIdentity),
		);
	
		return token;
	}
}

export { NewSigningAuthority };