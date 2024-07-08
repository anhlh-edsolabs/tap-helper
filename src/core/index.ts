import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { ECPairFactory } from "ecpair";
import { randomBytes as rng } from "crypto";

bitcoin.initEccLib(ecc);

const ECPair = ECPairFactory(ecc);

export { bitcoin, ECPair, ecc, rng };
