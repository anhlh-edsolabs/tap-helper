# Tap Protocol helper library

Helper functions for signing TAP protocol inscriptions.

## Description

[![npm version](https://badge.fury.io/js/tap-protocol-helper.svg)](https://badge.fury.io/js/tap-protocol-helper)

This package provides a set of helper scripts designed to facilitate the creation of signed authority inscriptions for the Tap Protocol. It includes functionality for signing authentication messages, token authentication, and token redemption using various cryptographic protocols.

## Installation

To install the necessary dependencies, run the following command:

```sh
yarn add tap-protocol-helper
```

or

```sh
npm install tap-protocol-helper
```

## Usage

To use the Tap Helper functions, you can import the Tap and Utils modules into your project as follows:

```JavaScript
const { Tap, Utils } = require("tap-protocol-helper");
const { ECPair } = require("./dist/src/core");
```

### 1. Signing a `privilege-auth` inscription

Use the `signAuth` function to sign a `privilege-auth` message:

```JavaScript
const keypair = ECPair.makeRandom(); // Replace with your keypair generation method
const msgKey = "auth";
const message = { name: "tap-protocol-privilege-auth-000" };
const salt = Math.random(); // Optional: Provide your own salt value

const priv_auth = Tap.signAuth(keypair.privateKey, keypair.publicKey, msgKey, message, salt);
```

**Example output:**

```JavaScript
{
    test: {
        valid: true,
        pub: "0282984730b88570f86c56d475d90258d1ca9755373e18fabc130791923f9e0f4a",
        pubRecovered: "0282984730b88570f86c56d475d90258d1ca9755373e18fabc130791923f9e0f4a"
    },
    result: '{"p":"tap","op":"privilege-auth","sig":{"v":"0","r":"16305713734998215074335603060711813150048114674529647022075032070990566113517","s":"40018336075309720814901490213864323243237297900828141635735508366496148314591"},"hash":"8fa604b40f239c27995d58c773eb846c9122cc77541d1a0ac770ba4a52f4abcc","salt":"0.4840164898423085","auth":{"name":"tap-protocol-privilege-auth-000"}}'
}
```

The `result` field in the output above is the signed inscription text to be inscribed:

```JSON
{
    "p": "tap",
    "op": "privilege-auth",
    "sig": {
        "v": "0",
        "r": "16305713734998215074335603060711813150048114674529647022075032070990566113517",
        "s": "40018336075309720814901490213864323243237297900828141635735508366496148314591"
    },
    "hash": "8fa604b40f239c27995d58c773eb846c9122cc77541d1a0ac770ba4a52f4abcc",
    "salt": "0.4840164898423085",
    "auth": { "name": "tap-protocol-privilege-auth-000" }
}
```

### 2. Signing a `token-mint` inscription

Use `signMint` to create a `token-mint` inscription text

```JavaScript
const keypair = ECPair.makeRandom(); // Replace with your keypair generation method
const ticker = "tap-token-auth";
const amount = 1000;
const salt = Math.random(); // Optional: Provide your own salt value
const minter = 'tb1p96fnzkff6af94z0zpaahqws45rjcw5fd6wk3pe2w7cqz279wl6rqzw0k37'

const mint_auth = signMint(keypair.privateKey, keypair.publicKey, ticker, amount, minter, salt);
```

**Example output:**

```JavaScript
{
    test: {
        valid: true,
        pub: "02801d73a46adffac2a0bc9bddce670a64b99e97df87a1c86aa38dab8f642cdcdd",
        pubRecovered: "02801d73a46adffac2a0bc9bddce670a64b99e97df87a1c86aa38dab8f642cdcdd"
    },
    result: '{"p":"tap","op":"token-mint","tick":"tap-token-auth","amt":1000,"prv":{"sig":{"v":"0","r":"28840735240323581642649166158114847033326200650757009309461520982937724983138","s":"43031653986158326967040449621257596604714194318555432467794807862498111678116"},"hash":"b117c449ebba4b9f033ad46daa55a1004369463cdc757bd98a27ac05317e7165","address":"tb1p96fnzkff6af94z0zpaahqws45rjcw5fd6wk3pe2w7cqz279wl6rqzw0k37","salt":"0.4840164898423085"}}'
}
```

The inscription text to be inscribed:

```JSON
{
    "p": "tap",
    "op": "token-mint",
    "tick": "tap-token-auth",
    "amt": 1000,
    "prv": {
        "sig": {
            "v": "0",
            "r": "28840735240323581642649166158114847033326200650757009309461520982937724983138",
            "s": "43031653986158326967040449621257596604714194318555432467794807862498111678116"
        },
        "hash": "b117c449ebba4b9f033ad46daa55a1004369463cdc757bd98a27ac05317e7165",
        "address": "tb1p96fnzkff6af94z0zpaahqws45rjcw5fd6wk3pe2w7cqz279wl6rqzw0k37",
        "salt": "0.4840164898423085"
    }
}
```
