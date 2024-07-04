import { Buffer } from "buffer";

export function toBigInt(buffer: Buffer): bigint {
	return BigInt("0x" + buffer.toString("hex"));
}

export function toBigIntStr(buffer: Buffer): string {
	return toBigInt(buffer).toString();
}

export function fromBigInt(input: bigint, length: number = 64): Buffer {
	return Buffer.from(input.toString(16).padStart(length, "0"), "hex");
}

export function fromBigIntStr(input: string, length: number = 64): Buffer {
	return fromBigInt(BigInt(input), length);
}
