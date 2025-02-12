import secrets
from mnemonic import Mnemonic

languages = [
    "english",
    "chinese_simplified",  
    "chinese_traditional",  
    "spanish",  
    "french",  
    "italian",  
    "japanese",  
    "korean",  
    "portuguese",  
    "russian"  
]

# [BIP39] Initializing the instance to the desired language (English)
mnemo = Mnemonic(language=languages[0])
# [BIP39] Getting the word list from BIP-39
bip39_words = mnemo.wordlist

# [Entropy] Generate 128 bits binary entropy
entropy = (bin(secrets.randbits(128))[2:]).zfill(128)


# [Padding] Fill with zeros up to 64 bits
binary_len_entropy_64bits = bin(128)[2:].zfill(64)
# [Padding] Finalized
prepared_entropy = entropy + "1" + ("0" * 319) + binary_len_entropy_64bits

# [SHA-256] State Values
state_values = {'H0': '6a09e667', 'H1': 'bb67ae85', 'H2': '3c6ef372', 'H3': 'a54ff53a', 'H4': '510e527f', 'H5': '9b05688c', 'H6': '1f83d9ab', 'H7': '5be0cd19'}
H = list(state_values.keys())
# [SHA-256] SHA-256 internal operations functions
def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

# [SHA-256] Creating a vector of words W0 to W15
W = [int(prepared_entropy[i:i+32], 2) for i in range(0, 512, 32)]
# [SHA-256] Expanding to W63
for i in range(16, 64):
    W.append((sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]) & 0xFFFFFFFF)

# [SHA-256] Compression Functions
def Ch(x, y, z):
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

# [SHA-256] Round constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
# [SHA-256] Initial Hash Vectors H0 to H7 (SHA-256 constants)
initial_H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]
# [SHA-256] Temporary Variables
a, b, c, d, e, f, g, h = initial_H
# [SHA-256] Processed each round of SHA-256
for i in range(64):
    t1 = (h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]) & 0xFFFFFFFF
    t2 = (Sigma0(a) + Maj(a, b, c)) & 0xFFFFFFFF
    h = g
    g = f
    f = e
    e = (d + t1) & 0xFFFFFFFF
    d = c
    c = b
    b = a
    a = (t1 + t2) & 0xFFFFFFFF
# [SHA-256] Refresh hash values
H = [
    (initial_H[0] + a) & 0xFFFFFFFF,
    (initial_H[1] + b) & 0xFFFFFFFF,
    (initial_H[2] + c) & 0xFFFFFFFF,
    (initial_H[3] + d) & 0xFFFFFFFF,
    (initial_H[4] + e) & 0xFFFFFFFF,
    (initial_H[5] + f) & 0xFFFFFFFF,
    (initial_H[6] + g) & 0xFFFFFFFF,
    (initial_H[7] + h) & 0xFFFFFFFF
]
# [SHA-256] Final Hash
hash_result = ''.join(format(x, '08x') for x in H)
# [SHA-256] Converting the hash from hexadecimal to 256 Bits binary
hash_bin = bin(int(hash_result, 16))[2:].zfill(256)

# [Checksum] Extracting the checksum from the first 4 bits of the binary hash
checksum = hash_bin[:4]

# [Entropy] Full 132-bit entropy with checksum included
entropy_132bits = entropy + checksum

# [Seed-Phrase] Dividing the 132 Bits of entropy into 12 groups of 11 bits and calculating their decimal representation
seed = ''
for n in range(0, len(entropy_132bits), 11):
    binEntropy = entropy_132bits[n:n + 11]
    indexBip39 = int(binEntropy, 2)
    word = bip39_words[indexBip39]
    #print(f'{binEntropy} : [{indexBip39}] - {word}')
    seed = seed + ' ' + word

seed = seed.strip()
print('Valid Check:', mnemo.check(seed))
print(seed)
input('Press any key to exit:')