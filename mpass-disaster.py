#!/usr/bin/python3
import json
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
from lighthive.datastructures import Operation

def disasterkey_to_wif(pubkey):
    return "CZD" + b58encode(b'\xbb' + pubkey + sha256(sha256(b'\xbb' + pubkey).digest()).digest()[:4]).decode("ascii")

def pubkey_to_compressed(pubkey):
    x = pubkey.point.x.to_bytes(32, byteorder='big')
    yred = (2 + pubkey.point.y % 2).to_bytes(1, byteorder='big')
    cpubkey = yred + x
    hash1 = hashlib.new('ripemd160')
    hash1.update(cpubkey)
    checksum = hash1.digest()[:4]
    return cpubkey + checksum

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
        self.username = username
        self.owner = key_from_creds(username, "owner", password)
        self.active = key_from_creds(username, "active", password)
        self.disaster = key_from_creds(username, self.scope, password)
        activekey = PrivateKey.fromString(hexlify(self.active))
        active_public = pubkey_to_compressed(activekey.publicKey())
        self.client = Client()
        b58key = "STM" + b58encode(active_public).decode("ascii")
        keyrefs = self.client.get_key_references([b58key])
        if not keyrefs[0] or keyrefs[0][0] != username:
            raise RuntimeError("ERROR: User and password don't match with HIVE account.")
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
        return blake2b(b"".join(chunks),
                       digest_size=self.keylen,
                       key=hashing_salt,
                       encoder=RawEncoder)

    def paperwallet(self):
        return bip39.encode_bytes(self.disaster)

    def owner_sign(self, data):
        ecdsa_signingkey = PrivateKey.fromString( hexlify(self.owner))
        sig =  ecdsa.Ecdsa.sign(data.decode("latin1"), ecdsa_signingkey)
        return sig.toDer(withRecoveryId=True)

    def update_account_json(self):
        account_obj = json.loads(self.client.get_accounts([self.username])[0]["json_metadata"])
        pubkey = self.disaster_pubkey()
        sig = self.owner_sign(pubkey)
        keyinfo = {}
        keyinfo["key"] = disasterkey_to_wif(pubkey)
        keyinfo["sig"] = b58encode(sig).decode("latin1")
        account_obj["coinzdense_disaster_recovery"] = keyinfo
        newjson = json.dumps(account_obj)
        active = to_priv_repr(self.active)
        c = Client(keys=[active])
        ops = [
            Operation('account_update', 
                      {
                        'account': self.username,
                        'json_metadata': newjson
                      }
                     )
        ]
        c.broadcast(ops)

def main():
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    password = getpass("Password for " + username + ": ")
    account = HiveAccount(username, password=password)
    account.update_account_json()
    print("Registered disaster recovery key")

if __name__ == "__main__":
    main()
