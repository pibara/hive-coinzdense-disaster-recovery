#!/usr/bin/python3
from sys import argv
from base58 import b58decode, b58encode
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve import ecdsa
from binascii import hexlify, unhexlify
from getpass import getpass
from libnacl import crypto_kdf_keygen
from libnacl import crypto_kdf_derive_from_key
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
import bip39
from hashlib import sha256, sha512
import hashlib
from lighthive.client import Client
from lighthive.exceptions import RPCNodeException

def disasterkey_to_wif(pubkey):
    return "CZD" + b58encode(b'\xbb' + pubkey + sha256(sha256(b'\xbb' + pubkey).digest()).digest()[:4]).decode("ascii")

def pubkey_to_compressed(pubkey):
    x = pubkey.point.x.to_bytes(32, byteorder='big')
    yred = (2 + pubkey.point.y % 2).to_bytes(1, byteorder='big')
    cpubkey = yred + x
    return cpubkey + sha256(sha256(cpubkey).digest()).digest()[:4] #FIXME: The WIF checksum seems different for pub/priv ???

def pubkey_to_uncompressed(pubkey):
    x = pubkey.point.x.to_bytes(32, byteorder='big')
    y = pubkey.point.y.to_bytes(32, byteorder='big')
    prefix = (4).to_bytes(1, byteorder='big')
    return prefix + x + y

def key_from_creds(account, role, password):
    seed = account + role + password
    return sha256(seed.encode("latin1")).digest()

def to_priv_repr(binary):
    return b58encode(b'\x80' + binary + sha256(sha256(b'\x80' + binary).digest()).digest()[:4]).decode("ascii")

class HiveAccount:
    def __init__(self, username, password):
        self.scope = "disaster"
        self.keylen = 32
        self.owner = key_from_creds(username, "owner", password)
        self.posting = key_from_creds(username, "posting", password)
        self.disaster = key_from_creds(username, self.scope, password)
        postingkey = PrivateKey.fromString(hexlify(self.posting))
        posting_public = pubkey_to_compressed(postingkey.publicKey())
        print("DEBUG:", hexlify(posting_public).decode("ascii"))
        print("DEBUG:", hexlify(b58decode("7NnGYwhwPqeoUARJiWJCqp5bFxbSnNUG1fjRLxD4xnp9SJrwPE")).decode("ascii"))
        client = Client()
        b58key = b58encode(posting_public).decode("ascii")
        print("DEBUG:", b58key)
        print("DEBUG:", "7NnGYwhwPqeoUARJiWJCqp5bFxbSnNUG1fjRLxD4xnp9SJrwPE")
        try:
            keyrefs = client.get_key_references([b58key])
            if keyrefs[0][0] != username:
                print("ERROR: User and password don't match with HIVE account, ignore for now")
        except RPCNodeException:
            print("ERROR: Invalid posting key according to lighthive, ignore for now")
    def disaster_pubkey(self):
        # Derive a salt for hashing operations from the private key
        hashing_salt = crypto_kdf_derive_from_key(self.keylen, 0, self.scope, self.disaster)
        # Derive a list of 32 pairs of byte-signing private keys
        chunks = [crypto_kdf_derive_from_key(self.keylen, x, self.scope, self.disaster) for x in list(range(1, self.keylen*2+1))]
        # Hash each of the 32 pairs of byte-signing private keys 256 times to get the byte signing public keys
        for _ in range(0,256):
            for idx in range(0,self.keylen*2):
                chunks[idx] = blake2b(chunks[idx],
                                      digest_size=self.keylen,
                                      key=hashing_salt,
                                      encoder=RawEncoder)
        #FIXME: This could be a flat hash instead of a merkletree.
        # Reduce the 32 pairs of byte-signing public keys to a single merkle-tree root
        while len(chunks) > 1:
            chunks = [blake2b(chunks[x*2] + chunks[x*2+1],
                              digest_size=self.keylen,
                              key=hashing_salt,
                              encoder=RawEncoder) for x in range(0, len(chunks)//2)]
        return chunks[0]

    def paperwallet(self):
        return bip39.encode_bytes(self.disaster)

    def owner_sign(self, data):
        ecdsa_signingkey = PrivateKey.fromString( hexlify(self.owner))
        sig =  ecdsa.Ecdsa.sign(data.decode("latin1"), ecdsa_signingkey)
        return sig.toDer(withRecoveryId=True)


def main():
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    password = getpass("Password for " + username + ": ")
    account = HiveAccount(username, password=password)
    print("Disaster pubkey:")
    pubkey = account.disaster_pubkey()
    print(" *", disasterkey_to_wif(pubkey))
    sig = account.owner_sign(pubkey)
    print("ECDSA Signature:")
    print(" *", b58encode(sig).decode("latin1"))

if __name__ == "__main__":
    main()
