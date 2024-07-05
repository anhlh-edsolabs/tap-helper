import { PrivAuthProtocol } from "../src/types";
import { getKeypairBuff, sign, signAndVerify, verify } from "../src/utils";

const keypair = {
	pk: "6c94b29a47f0f4b7380f2f3975a612d4f5db4b56bbe8471d258ba3e125dbdce5",
	pub: "03087906bf9472c7db48daee1478b7e70f4b3ce01436a241e3418b72ecdc87884b",
};

describe("sign function", () => {
	it("should return a valid signature and message hash", () => {
		const message = "test_message";
		const privKeyBuffer = Buffer.from(keypair.pk, "hex");
		const salt = "test_salt";
		const { signature, msgHash } = sign(message, privKeyBuffer, salt);
		expect(signature).toBeDefined();
		expect(msgHash).toBeDefined();
		// Additional checks can be added here to validate the signature and msgHash further
	});

	it("should throw an error when signing fails", () => {
		const message = "test_message";
		const privKeyBuffer = Buffer.from("test_privKey");
		const salt = "test_salt";
		expect(() => sign(message, privKeyBuffer, salt)).toThrow(
			"Failed to sign the message: TypeError: Expected Private",
		);
	});
});

describe("verify function", () => {
	const verifyingHash = Buffer.from(
		"5471b88a5e721a74fa4d75a3c95fa045e951643c948fdd79af5fa5d10ac99e1a",
		"hex",
	);
	const pubKeyBuffer = Buffer.from(keypair.pub, "hex");
	const signature = {
		v: "0",
		r: "34249651214269469717861213398711965184800430928931385332066625619914023697843",
		s: "36706060356166294409252831878099979084287150562193464995607767095211250500217",
	};

	it("should return a valid verification result", () => {
		const result = verify(verifyingHash, pubKeyBuffer, signature);
		expect(result.isValid).toBe(true);
		expect(result.pubRecovered).toBe(keypair.pub);
	});

	it("should throw an error when verification fails", () => {
		const invalidSignature = {
			v: "0",
			r: "0",
			s: "0",
		};
		expect(() =>
			verify(verifyingHash, pubKeyBuffer, invalidSignature),
		).toThrow(
			"Failed to recover the public key: TypeError: Expected Signature",
		);
	});
});

describe("signAndVerify function", () => {
	const keypair = {
		pk: "6c94b29a47f0f4b7380f2f3975a612d4f5db4b56bbe8471d258ba3e125dbdce5",
		pub: "03087906bf9472c7db48daee1478b7e70f4b3ce01436a241e3418b72ecdc87884b",
	};

	it("should sign and verify a message correctly", () => {
		const message = "test_message";
		const privKeyBuffer = Buffer.from(keypair.pk, "hex");
		const salt = "test_salt";
		const { signature, msgHash } = sign(message, privKeyBuffer, salt);
		const { isValid, pubRecovered } = verify(
			msgHash,
			Buffer.from(keypair.pub, "hex"),
			signature,
		);

		expect(signature).toBeDefined();
		expect(msgHash).toBeDefined();
		expect(isValid).toBe(true);
		expect(pubRecovered).toBe(keypair.pub);
	});

	it("should sign and verify a message with a null message key correctly", () => {
		const keypairBuff = getKeypairBuff(keypair.pk, keypair.pub);
		const baseMessage = "test_baseMessage";
		const messageKey = null;

		const protocol: PrivAuthProtocol = {
			p: "tap",
			op: "privilege-auth",
			sig: null,
			hash: null,
			salt: "test_salt",
		};

		const result = signAndVerify(
			protocol,
			keypairBuff,
			baseMessage,
			messageKey,
		);

		expect(result.test.valid).toBe(true);
		expect(result.test.pub).toBe(keypairBuff.pubKeyBuffer.toString("hex"));
		expect(result.test.pubRecovered).toBe(
			keypairBuff.pubKeyBuffer.toString("hex"),
		);
		expect(result.result).toBe(JSON.stringify(protocol));
	});

	it("should sign and verify a message with a message key correctly", () => {
		const keypairBuff = getKeypairBuff(keypair.pk, keypair.pub);

		// message must be an arbitrary JSON object
		const message = {
			message: "test_baseMessage",
		};
		const messageKey = "auth";

		const protocol: PrivAuthProtocol = {
			p: "tap",
			op: "privilege-auth",
			sig: null,
			hash: null,
			salt: "test_salt",
			[messageKey]: message,
		};

		const baseMessage = JSON.stringify(protocol[messageKey]);

		const verification = signAndVerify(
			protocol,
			keypairBuff,
			baseMessage,
			messageKey,
		);

		expect(verification.test.valid).toBe(true);
		expect(verification.test.pub).toBe(keypairBuff.pubKeyBuffer.toString("hex"));
		expect(verification.test.pubRecovered).toBe(
			keypairBuff.pubKeyBuffer.toString("hex"),
		);
		expect(verification.result).toBe(JSON.stringify(protocol));
		expect(JSON.parse(verification.result).auth).toStrictEqual(message);
	});
});
