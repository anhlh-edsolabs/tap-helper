interface KeypairBuffer {
	privKeyBuffer: Buffer;
	pubKeyBuffer: Buffer;
}

interface VerificationResult {
	test: {
		valid: boolean;
		pub: string;
		pubRecovered: string;
	};
	result: string;
}

interface Signature {
	r: string;
	s: string;
	v: string;
}

declare type Operation = "privilege-auth" | "token-mint" | "dmt-mint" | "token-auth";

interface BaseProtocol {
	p: string | "tap";
	op: Operation;
	// sig: Signature | null;
	// hash: string | null;
	// salt: string;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	[key: string]: any;
}

interface PrivAuthProtocol extends BaseProtocol {
	op: Operation | "privilege-auth";
	sig: Signature | null;
	hash: string | null;
	salt: string;
}

interface TapMintProtocol extends BaseProtocol {
	op: "token-mint";
	tick: string;
	amt: number;
	prv: {
		sig: Signature | null;
		hash: string | null;
		address: string;
		salt: string;
	};
}

interface DmtMintProtocol extends BaseProtocol {
	op: "dmt-mint";
	tick: string;
	blk: number;
	dep: string;
	prv: {
		sig: Signature | null;
		hash: string | null;
		address: string;
		salt: string;
	};
}

interface VerificationProtocol extends PrivAuthProtocol {
	address: string;
	prv: string;
	verify: string;
	col: string;
	seq: number;
}

interface TokenAuthProtocol extends PrivAuthProtocol {
	op: "token-auth";
	sig: Signature | null;
	hash: string | null;
	salt: string;
}

export type { KeypairBuffer, VerificationResult, Signature };

export type {
	BaseProtocol,
	PrivAuthProtocol,
	TapMintProtocol,
	DmtMintProtocol,
	VerificationProtocol,
	TokenAuthProtocol,
};
