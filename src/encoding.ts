import { X509Certificate } from 'node:crypto';
import { V2 as paseto } from 'paseto';

export namespace ed25519 {
	export type PublicKey = Buffer;
	export type PrivateKey = Buffer;
}

/**
 * @internal
 */
export const pemToPubkey = (key: string): ed25519.PublicKey => {
	console.log(key);
	const x509 = new X509Certificate(key);

	const { publicKey: pub } = x509;

	if (pub.asymmetricKeyType !== 'ed25519') {
		throw new Error(`unknown public type ${pub.asymmetricKeyType}`);
	}

	const pubkey = paseto.keyObjectToBytes(pub);
	return pubkey;
};
