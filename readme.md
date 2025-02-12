# BTC Seed Phrase Generator

This script generates a **Bitcoin Seed Phrase** following the **BIP-39** standard. It details the entire process of entropy generation, checksum calculation, and conversion to BIP-39 word lists.

## How it works?

The script performs the following steps:

1. **Entropy Generation:** Creates a random 128-bit sequence.
2. **Padding and Filling:** Adds extra bits to comply with BIP-39.
3. **Checksum Calculation:** Applies SHA-256 to the entropy and extracts the first 4 bits.
4. **Seed Phrase Generation:** Converts the final 132 bits into 12 words from the BIP-39 list.
5. **Validation Check:** Confirms that the generated Seed Phrase is valid.

## Dependencies

To run this script, you need to install the `mnemonic` library. Install it using the following command:

```sh
pip install mnemonic
```

## How to run

Save the code as `script.py` and execute:

```sh
python script.py
```

## Example output

```sh
Valid Check: True
apple dog banana ...
```

## Warning ⚠️

**This code is for educational purposes only and should not be used to generate real keys.**

