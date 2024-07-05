import { sha256 as bcSha256 } from "bitcoinjs-lib/src/crypto";
import { ecc } from "./core";
import * as SBuffer from "./core/buffer";
import {
	BaseProtocol,
	KeypairBuffer,
	Signature,
	VerificationResult,
} from "./types";
import { RecoverableSignature, RecoveryIdType } from "tiny-secp256k1";

/**
 * Signs a message using a private key and a salt.
 * @param message - The message to be signed.
 * @param privKeyBuffer - The private key buffer.
 * @param salt - The salt to be appended to the message before signing.
 * @returns An object containing the signature and the message hash.
 */
export function sign(
	message: string,
	privKeyBuffer: Buffer,
	salt: string,
): { signature: Signature; msgHash: Buffer } {
	if (
		typeof message !== "string" ||
		!Buffer.isBuffer(privKeyBuffer) ||
		typeof salt !== "string"
	) {
		throw new Error("Invalid input types");
	}
	try {
		const msgHash: Buffer = sha256(`${message}${salt}`);
		const recoverableSig = ecc.signRecoverable(msgHash, privKeyBuffer);

		const signature = splitSignature(recoverableSig);

		return { signature, msgHash };
	} catch (error: unknown) {
		throw new Error(`Failed to sign the message: ${error}`);
	}
}

/**
 * Verifies the signature of a hash using the provided public key and signature.
 * @param hash - The hash to be verified.
 * @param pubKeyBuffer - The public key buffer.
 * @param signature - The signature to be verified. { Signature: { r: string; s: string; v: string; }}
 * @param protocol - The protocol object. { BaseProtocol: { p: string | "tap"; op: Operation; [key: string]: any; }}
 * @returns The verification result.
 * { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function verify(
	hash: Buffer,
	pubKeyBuffer: Buffer,
	signature: Signature,
	protocol: BaseProtocol,
): VerificationResult {
	const sig = joinSignature(signature);
	const isValid = ecc.verify(hash, pubKeyBuffer, sig.signature);
	const pubRecovered = Buffer.from(
		ecc.recover(hash, sig.signature, sig.recoveryId, true) ??
			new Uint8Array(33),
	).toString("hex");

	return {
		test: {
			valid: isValid,
			pub: pubKeyBuffer.toString("hex"),
			pubRecovered,
		},
		result: JSON.stringify(protocol),
	} as VerificationResult;
}

/**
 * Signs and verifies a message using the specified protocol, keypair, base message, and optional message key.
 * @param protocol - The protocol object containing the necessary information for signing and verifying.
 * { BaseProtocol: { p: string | "tap"; op: Operation; [key: string]: any;}
 * @param keypair - The keypair object containing the private and public keys.
 * { KeypairBuffer: { privKeyBuffer: Buffer; pubKeyBuffer: Buffer; }}
 * @param baseMessage - The base message to be signed and verified.
 * @param messageKey - The optional message key to be used instead of the base message.
 * @returns The verification result indicating whether the message is valid or not.
 * { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function signAndVerify(
	protocol: BaseProtocol,
	keypair: KeypairBuffer,
	baseMessage: string,
	messageKey: string | null = null,
): VerificationResult {
	const salt = protocol.prv ? protocol.prv.salt : protocol.salt;

	const { signature, msgHash } = sign(
		baseMessage,
		keypair.privKeyBuffer,
		salt,
	);

	protocol.prv ? (protocol.prv.sig = signature) : (protocol.sig = signature);
	protocol.prv
		? (protocol.prv.hash = msgHash.toString("hex"))
		: (protocol.hash = msgHash.toString("hex"));

	const test_protocol = { ...protocol };
	// if messageKey is null or undefined or empty string, then use baseMessage
	const test_message = messageKey
		? JSON.stringify(test_protocol[messageKey])
		: baseMessage;
	const test_msgHash = sha256(`${test_message}${salt}`);
	const test_sig = test_protocol.prv
		? test_protocol.prv.sig
		: test_protocol.sig;

	return verify(test_msgHash, keypair.pubKeyBuffer, test_sig, protocol);
}

/**
 * Calculates the SHA256 hash of the input.
 *
 * @param input - The input string or buffer to calculate the hash for.
 * @returns The SHA256 hash as a buffer.
 */
export function sha256(input: string | Buffer): Buffer {
	if (typeof input === "string") {
		return bcSha256(Buffer.from(input));
	}
	return bcSha256(input);
}

/**
 * Splits a recoverable signature into its components.
 * @param sig - The recoverable signature to split.
 * { RecoverableSignature: { signature: Uint8Array; recoveryId: RecoveryIdType; }
 * @param outputFormat - The format of the output components. Default is "number".
 * @returns The signature components.
 */
export function splitSignature(
	sig: RecoverableSignature,
	outputFormat: "number" | "hex" = "number",
): Signature {
	const signature = sig.signature;

	if (!(signature instanceof Uint8Array)) {
		throw new Error("Invalid signature type");
	}
	if (signature.length !== 64) {
		throw new Error("Invalid signature length");
	}

	const r = Buffer.from(signature.slice(0, 32));
	const s = Buffer.from(signature.slice(32, 64));

	switch (outputFormat) {
		case "hex":
			return {
				v: sig.recoveryId.toString(),
				r: r.toString("hex"),
				s: s.toString("hex"),
			} as Signature;
		case "number":
		default:
			return {
				v: sig.recoveryId.toString(),
				r: SBuffer.toBigIntStr(r),
				s: SBuffer.toBigIntStr(s),
			} as Signature;
	}
}

/**
 * Converts a signature object to a recoverable signature object.
 * @param sig - The signature object to convert. { Signature: { r: string; s: string; v: string; }
 * @returns The recoverable signature object.
 * { RecoverableSignature: { signature: Uint8Array; recoveryId: RecoveryIdType; }}
 */
export function joinSignature(sig: Signature): RecoverableSignature {
	// check if sig is of type Signature, otherwise throw an error
	if (typeof sig !== "object" || sig === null) {
		throw new Error("Invalid signature type");
	}
	if (
		typeof sig.r !== "string" ||
		typeof sig.s !== "string" ||
		typeof sig.v !== "string"
	) {
		throw new Error("Invalid signature format");
	}

	const r = SBuffer.fromBigIntStr(sig.r);
	const s = SBuffer.fromBigIntStr(sig.s);

	return {
		signature: Buffer.concat([r, s]) as Uint8Array,
		recoveryId: Number(sig.v) as RecoveryIdType,
	} as RecoverableSignature;
}

/**
 * Converts private and public keys to buffers and returns them as a keypair buffer object.
 * @param privKey - The private key as a string or buffer.
 * @param pubKey - The public key as a string or buffer.
 * @returns The keypair buffer object containing the private and public key buffers.
 */
export function getKeypairBuff(
	privKey: string | Buffer,
	pubKey: string | Buffer,
): KeypairBuffer {
	const privKeyBuffer = Buffer.isBuffer(privKey)
		? privKey
		: Buffer.from(privKey, "hex");
	const pubKeyBuffer = Buffer.isBuffer(pubKey)
		? pubKey
		: Buffer.from(pubKey, "hex");

	if (privKeyBuffer.length !== 32 || pubKeyBuffer.length !== 33) {
		throw new Error("Invalid key length");
	}

	return { privKeyBuffer, pubKeyBuffer } as KeypairBuffer;
}

export {};
