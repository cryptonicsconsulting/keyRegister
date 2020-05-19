# Key Register - File Access Delegation Smart Contract and JavaScript Library

## Purpose 

This smart contract allows delegating access to encrypted data hosted on a given URI. 

Data the the URI is expected to be encrypted with **AES-256-CBC**. A register allows Ethereum account owners to provide a public key for encryption. This public key can used to encrypt the AES key securing the data for this specific user using **ECIES**.

Access revocation consists in removing the key from the Register.

**Notes:**

- It is advisable to use a EC key pair unrelated to the Ethereum account of the user. 
- Any 256-bit EC curve can work with the contract, but the provided Library uses **secp256k1**.
- EC public keys are expressed as x and y values on the curve (32-bit each) for efficiency. The library facilitates conversion to this format.

Usage examples can be found in the [unit tests](https://github.com/cryptonicsconsulting/keyRegister/blob/master/test/keyRegister.js).

## Crypto Library

The JavaScript is implemented in [CryptoLib.js](https://github.com/cryptonicsconsulting/keyRegister/blob/master/cryptoLib.js). 

It uses crypto primitives built into Node.js (which in turn uses OpenSSL) and [eccrypto](https://github.com/bitchan/eccrypto).

Keys are expressed as strings in hex notation with leading '0x' to facilitate interacting with web3.js.

## Smart Contract

The smart contract is implemented in [KeyRegister.sol](https://github.com/cryptonicsconsulting/keyRegister/blob/master/contracts/KeyRegister.sol).

