import * as Utils from "./utils";
import {
	KeypairBuffer,
	VerificationResult,
	PrivAuthProtocol,
	TapMintProtocol,
	DmtMintProtocol,
	VerificationProtocol,
	TokenAuthProtocol,
	RedeemData,
	RedeemItem,
} from "./types";

/**
 * Signs and verifies the authentication message using the provided keys and parameters.
 * @param privKey - The private key used for signing the message.
 * @param pubKey - The public key used for verifying the signature.
 * @param messageKey - The key used to identify the message in the protocol object.
 * @param message - The message to be signed and verified.
 * @param salt - The salt value used for generating the protocol object. Defaults to a random number if not provided.
 * @returns { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function signAuth(
	privKey: string | Buffer,
	pubKey: string | Buffer,
	messageKey: string,
	message: string | Record<string, unknown>,
	salt: number | string = Math.random(),
): VerificationResult {
	const keypair: KeypairBuffer = Utils.getKeypairBuff(privKey, pubKey);

	const protocol: PrivAuthProtocol = {
		p: "tap",
		op: "privilege-auth",
		sig: null,
		hash: null,
		salt: "" + salt,
		[messageKey]: message,
	};

	const baseMessage = JSON.stringify(message);
	return Utils.signAndVerify(protocol, keypair, baseMessage, messageKey);
}

/**
 * Signs and mints a token using the provided parameters.
 * @param privKey - The private key used for signing.
 * @param pubKey - The public key used for verification.
 * @param ticker - The ticker symbol of the token.
 * @param amount - The amount of tokens to mint.
 * @param address - The address where the minted tokens will be sent.
 * @param salt - The salt value used for generating the signature. Defaults to a random value.
 * @returns { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function signMint(
	privKey: string | Buffer,
	pubKey: string | Buffer,
	ticker: string,
	amount: number,
	address: string,
	salt: number | string = Math.random(),
): VerificationResult {
	const keypair: KeypairBuffer = Utils.getKeypairBuff(privKey, pubKey);

	const protocol: TapMintProtocol = {
		p: "tap",
		op: "token-mint",
		tick: ticker.toLowerCase(),
		amt: amount,
		prv: {
			sig: null,
			hash: null,
			address: address,
			salt: "" + salt,
		},
	};

	const baseMessage = `${protocol.p}-${protocol.op}-${protocol.tick}-${protocol.amt}-${protocol.prv.address}-`;
	return Utils.signAndVerify(protocol, keypair, baseMessage);
}

/**
 * Signs a DMT mint transaction and returns the verification result.
 * @param privKey - The private key used for signing the transaction.
 * @param pubKey - The public key associated with the private key.
 * @param ticker - The ticker symbol for the transaction.
 * @param block - The block number for the transaction.
 * @param dependency - The dependency for the transaction.
 * @param address - The address associated with the private key.
 * @param salt - The salt value for the transaction (optional, defaults to a random number).
 * @returns { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function signDmtMint(
	privKey: string | Buffer,
	pubKey: string | Buffer,
	ticker: string,
	block: number,
	dependency: string,
	address: string,
	salt: number | string = Math.random(),
): VerificationResult {
	const keypair: KeypairBuffer = Utils.getKeypairBuff(privKey, pubKey);

	const protocol: DmtMintProtocol = {
		p: "tap",
		op: "dmt-mint",
		tick: ticker.toLowerCase(),
		blk: block,
		dep: dependency,
		prv: {
			sig: null,
			hash: null,
			address: address,
			salt: "" + salt,
		},
	};

	const baseMessage = `${protocol.p}-${protocol.op}-${protocol.tick}-${protocol.blk}-${protocol.dep}-${protocol.prv.address}-`;
	return Utils.signAndVerify(protocol, keypair, baseMessage);
}

/**
 * Performs sign verification using the provided parameters.
 * @param privKey - The private key used for signing.
 * @param pubKey - The public key used for verification.
 * @param privilege_authority_id - The privilege authority ID.
 * @param sha256_hash - The SHA256 hash to verify.
 * @param collection - The collection name.
 * @param sequence - The sequence number.
 * @param address - The address.
 * @param salt - The salt value (optional, defaults to a random number).
 * @returns { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function signVerification(
	privKey: string | Buffer,
	pubKey: string | Buffer,
	privilege_authority_id: string,
	sha256_hash: string,
	collection: string,
	sequence: number,
	address: string,
	salt: number | string = Math.random(),
): VerificationResult {
	const keypair: KeypairBuffer = Utils.getKeypairBuff(privKey, pubKey);

	const protocol: VerificationProtocol = {
		p: "tap",
		op: "privilege-auth",
		sig: null,
		hash: null,
		address: address,
		salt: "" + salt,
		prv: privilege_authority_id,
		verify: sha256_hash,
		col: collection,
		seq: sequence,
	};

	const baseMessage = `${protocol.prv}-${protocol.col}-${protocol.verify}-${protocol.seq}-${protocol.address}-`;
	return Utils.signAndVerify(protocol, keypair, baseMessage);
}

/**
 * Signs a token authentication using the provided private and public keys.
 * @param privKey - The private key used for signing the token.
 * @param pubKey - The public key used for verifying the token.
 * @param authTokens - An array of authentication tokens to include in the signed token.
 * @param salt - The salt value used for generating the token.
 * @returns { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function signTokenAuth(
	privKey: string | Buffer,
	pubKey: string | Buffer,
	authTokens: string[] = [],
	salt: number | string = Math.random(),
): VerificationResult {
	return generateTokenAuthScript(privKey, pubKey, "auth", authTokens, salt);
}

/**
 * Signs a token redeem using the provided private key, public key, redeem items, authentication string, data string, and salt.
 * @param privKey - The private key used for signing the token redeem.
 * @param pubKey - The public key used for verifying the token redeem.
 * @param redeemItems - An array of redeem items.
 * @param auth - The authentication string.
 * @param data - The data string.
 * @param salt - The salt used for generating the token auth script. Defaults to a random number if not provided.
 * @returns { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
export function signTokenRedeem(
	privKey: string | Buffer,
	pubKey: string | Buffer,
	redeemItems: Array<RedeemItem> = [],
	auth: string = "",
	data: string = "",
	salt: number | string = Math.random(),
): VerificationResult {
	const message: RedeemData = {
		items: redeemItems,
		auth,
		data,
	};

	return generateTokenAuthScript(privKey, pubKey, "redeem", message, salt);
}

/**
 * Generates a token authentication script.
 *
 * @param privKey - The private key used for signing.
 * @param pubKey - The public key used for verification.
 * @param messageKey - The key used to store the message in the protocol object.
 * @param message - The message to be included in the protocol object.
 * @param salt - The salt value used for hashing (optional, default is a random number).
 * @returns { VerificationResult: { test: { valid: boolean; pub: string; pubRecovered: string; }; result: string; }}
 */
function generateTokenAuthScript(
	privKey: string | Buffer,
	pubKey: string | Buffer,
	messageKey: string,
	message: string[] | RedeemData,
	salt: number | string = Math.random(),
): VerificationResult {
	const keypair: KeypairBuffer = Utils.getKeypairBuff(privKey, pubKey);

	const protocol: TokenAuthProtocol = {
		p: "tap",
		op: "token-auth",
		sig: null,
		hash: null,
		salt: "" + salt,
		[messageKey]: message,
	};

	const baseMessage = JSON.stringify(message);
	return Utils.signAndVerify(protocol, keypair, baseMessage, messageKey);
}

export {};
