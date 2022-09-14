// Replit's modified PASETO implementation.
// https://github.com/replit/go-replidentity/blob/main/paserk/paserk.go

import blake2b from 'blake2b';
import { Buffer } from 'node:buffer';

import { api } from '../api/signing';
import { ed25519 } from '../encoding';

/**
 * @internal
 * PaserkPublicHeader is the header of a PASERK public key:
 * https://github.com/paseto-standard/paserk/blob/master/types/public.md
 */
export const PaserkPublicHeader = 'k2.public.';

/**
 * @internal
 * PaserkSecretHeader is the header of a PASERK secret key:
 * https://github.com/paseto-standard/paserk/blob/master/types/secret.md
 */
export const PaserkSecretHeader = 'k2.secret.';

/**
 * @internal
 * PaserkSIDHeader is the header of a PASERK sid:
 * https://github.com/paseto-standard/paserk/blob/master/types/sid.md
 */
export const PaserkSIDHeader = 'k2.sid.';

/**
 * @internal
 * PaserkPIDHeader is the header of a PASERK pid:
 * https://github.com/paseto-standard/paserk/blob/master/types/sid.md
 */
export const PaserkPIDHeader = 'k2.pid.';

/**
 * @internal
 * PaserkGSAIDHeader is the header of a PASERK [api.GovalSigningAuthority] id. This
 * is a replit extension to PASERK.
 */
export const PaserkGSAIDHeader = 'k2.gsaid.';

/**
 * @internal
 * paserkPublicLength is the expected length of a PASERK Public.
 */
export const paserkPublicLength = 53;

/**
 * @internal
 * paserkSecretLength is the expected length of a PASERK Secret.
 */
export const paserkSecretLength = 96;


/**
 * @internal
 * PASERKPublic is the serialized version of an [ed25519.PublicKey]:
 * https://github.com/paseto-standard/paserk/blob/master/types/public.md
 */
export type PASERKPublic = string;

/**
 * @internal
 * PASERKSecret is the serialized version of an [ed25519.PrivateKey]:
 * https://github.com/paseto-standard/paserk/blob/master/types/secret.md
 */
export type PASERKSecret = string;

/**
 * @internal
 * PublicKeyToPASERKPublic wraps an [ed25519.PublicKey] into its PASERK representation.
 */
export const PublicKeyToPASERKPublic = (pubkey: string): PASERKPublic => {
	return PaserkPublicHeader + Buffer.from(pubkey).toString('base64');
};

/**
 * @internal 
 * PASERKPublicToPublicKey unwraps an [ed25519.PublicKey] from its PASERK representation.
 */
export const PASERKPublicToPublicKey = (
	encoded: string,
): ed25519.PublicKey | null => {
	if (!encoded.startsWith(PaserkPublicHeader)) {
		throw new Error(
			`${encoded} does not have the ${PaserkPublicHeader} header`,
		);
	}

	if (encoded.length !== paserkPublicLength) {
		throw new Error(
			`${encoded} is not the expected length of ${paserkPublicLength}`,
		);
	}

	const rawKeyData = Buffer.from(
		Buffer.from(encoded.replace(PaserkPublicHeader, '')).toString('utf8'),
		'base64url',
	);

	return rawKeyData ? rawKeyData : null;
};

/**
 * @internal
 * PrivateKeyToPASERKSecret wraps an [ed25519.PrivateKey] into its PASERK representation.
 */
export const PrivateKeyToPASERKSecret = (privkey: string): PASERKSecret => {
	return PaserkSecretHeader + Buffer.from(privkey).toString('base64');
};

/**
 * @internal
 * PASERKSecretToPrivateKey unwraps an [ed25519.PrivateKey] from its PASERK representation.
 */
export const PASERKSecretToPrivateKey = (
	encoded: string,
): ed25519.PrivateKey | null => {
	if (!encoded.startsWith(PaserkSecretHeader)) {
		throw new Error(
			`${encoded} does not have the ${PaserkSecretHeader} header`,
		);
	}

	if (encoded.length !== paserkSecretLength) {
		throw new Error(
			`${encoded} is not the expected length of ${paserkSecretLength}`,
		);
	}

	const rawKeyData = Buffer.from(encoded.replace(PaserkSecretHeader, ''));

	return rawKeyData ? rawKeyData : null;
};

/**
 * @internal
 * paserkID implements the PASERK ID operation:
 * https://github.com/paseto-standard/paserk/blob/master/operations/ID.md
 */
export const paserkID = (header: string, data: string): string => {
	const h = blake2b(33);
	h.update(Buffer.from(header));
	h.update(Buffer.from(data));

	return header + h.digest('base64url');
};

/**
 * @internal
 * PaserkPID returns the PASERK ID of an [ed25519.PublicKey]:
 * https://github.com/paseto-standard/paserk/blob/master/types/pid.md
 */
export const PaserkPID = (pubkey: string): string => {
	return paserkID(PaserkPIDHeader, PublicKeyToPASERKPublic(pubkey));
};

/**
 * @internal
 * PaserkSID returns the PASERK ID of an [ed25519.PrivateKey]:
 * https://github.com/paseto-standard/paserk/blob/master/types/sid.md
 */
export const PaserkSID = (privkey: string): string => {
	return paserkID(PaserkSIDHeader, PrivateKeyToPASERKSecret(privkey));
};

/**
 * @internal
 * PaserkGSAID returns the PASERK ID of a [api.GovalSigningAuthority]. This is a Replit
 * extension to PASERK.
 */
export const PaserkGSAID = (authority: api.GovalSigningAuthority): string => {
	const serializedCertProto = api.GovalSigningAuthority.fromObject(authority);

	const certSerialized = Buffer.from(
		serializedCertProto.serializeBinary(),
	).toString('base64url');
	return paserkID(PaserkGSAIDHeader, certSerialized);
};
