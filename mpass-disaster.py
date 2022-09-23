#!/usr/bin/python3
"""Tool for handling hash-based one time disastery recovery keys for HIVE"""
import json
import sys
from sys import argv
import hashlib
from hashlib import sha256
from getpass import getpass
from binascii import hexlify
from enum import Enum
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve import ecdsa
from libnacl import crypto_kdf_keygen
from libnacl import crypto_kdf_derive_from_key
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
import bip39
from lighthive.client import Client
from lighthive.datastructures import Operation
from base58 import b58encode


class Keytype(Enum):
    """Enum class for key types"""
    QDRECOVERYPUBKEY = 1
    QDRECOVERYPRIVKEY = 2
    COINZDENSEPUBKEY = 3
    COINZDENSEPRIVKEY = 4
    ECDSACOMPRESSEDPUBKEY = 5
    ECDSAPRIVKEY = 6

class CheckSumType(Enum):
    """Enum class for checksum types"""
    DOUBLESHA256 = 1
    RIPEMD160 = 2

def key_to_wif(binkey, keytype):
    """Convert a binary key to WIF, depending on key type

    Parameters
    ----------
    binkey : bytes
               Binary public or private key
    keytype : Keytype
               The type of the key (enum)

    Returns
    -------
    string
        Base58 WIF of the key
    """
    csmap = {
        Keytype.QDRECOVERYPUBKEY: CheckSumType.RIPEMD160,
        Keytype.QDRECOVERYPRIVKEY: CheckSumType.DOUBLESHA256,
        Keytype.COINZDENSEPUBKEY: CheckSumType.RIPEMD160,
        Keytype.COINZDENSEPRIVKEY: CheckSumType.DOUBLESHA256,
        Keytype.ECDSACOMPRESSEDPUBKEY: CheckSumType.RIPEMD160,
        Keytype.ECDSAPRIVKEY: CheckSumType.DOUBLESHA256
    }
    netmap = {
        Keytype.QDRECOVERYPUBKEY: b'',
        Keytype.QDRECOVERYPRIVKEY: b'\xbb',
        Keytype.COINZDENSEPUBKEY: b'',
        Keytype.COINZDENSEPRIVKEY: b'\xbd',
        Keytype.ECDSACOMPRESSEDPUBKEY: b'',
        Keytype.ECDSAPRIVKEY: b'\x80'
    }
    prefixmap = {
        Keytype.QDRECOVERYPUBKEY: 'QRK',
        Keytype.QDRECOVERYPRIVKEY: '',
        Keytype.COINZDENSEPUBKEY: 'CZD',
        Keytype.COINZDENSEPRIVKEY: '',
        Keytype.ECDSACOMPRESSEDPUBKEY: 'STM',
        Keytype.ECDSAPRIVKEY: ''
    }
    fullkey = netmap[keytype] + binkey
    if csmap[keytype] == CheckSumType.DOUBLESHA256:
        checksum = sha256(sha256(fullkey).digest()).digest()[:4]
    elif csmap[keytype] == CheckSumType.RIPEMD160:
        hash1 = hashlib.new('ripemd160')
        hash1.update(fullkey)
        checksum = hash1.digest()[:4]
    return prefixmap[keytype] + b58encode(fullkey + checksum).decode("ascii")


def pubkey_to_compressed(pubkey):
    """Convert an ecdsa pubkey object to a compressed binary key

    Parameters
    ----------
    pubkey : ellipticcurve.PublicKey
               ECDSA pubkey object

    Returns
    -------
    bytes
            Binary compressed pubkey without WIF checksum
    """
    xval = pubkey.point.x.to_bytes(32, byteorder='big')
    yred = (2 + pubkey.point.y % 2).to_bytes(1, byteorder='big')
    return yred + xval

def key_from_creds(account, role, password):
    """Derive a key from the master password

    Parameters
    ----------
    account : string
               HIVE account name
    role : string
             owner/active/posting/disaster
    password : string
                 Master password for HIVE account

    Returns
    -------
    bytes
            Binary key for the given role and account.
    """
    seed = account + role + password
    return sha256(seed.encode("latin1")).digest()

class HiveAccount:
    """Class representing HIVE account."""
    def __init__(self, username, password):
        """Constructor"""
        self.scope = "disaster"
        self.keylen = 32
        self.username = username
        self.owner = key_from_creds(username, "owner", password)
        self.active = key_from_creds(username, "active", password)
        self.disaster = key_from_creds(username, self.scope, password)
        activekey = PrivateKey.fromString(hexlify(self.active))
        self.client = Client()
        b58key = key_to_wif(pubkey_to_compressed(activekey.publicKey()), Keytype.ECDSACOMPRESSEDPUBKEY)
        keyrefs = self.client.get_key_references([b58key])
        if not keyrefs[0] or keyrefs[0][0] != username:
            raise RuntimeError("ERROR: User and password don't match with HIVE account.")
    def _disaster_pubkey(self):
        """Derive the binary disaster recovery pubkey from the binary private key"""
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
        """The disaster recovery private key as list of words to write down as a paper wallet

        Returns
        -------
        string
            List of words to use as paper wallet
        """
        return bip39.encode_bytes(self.disaster)

    def get_privkey(self):
        """Get disaster recovery privkey as WIF

        Returns
        -------
        string
            Base58 representation of the disaster recovery private key.
        """
        return key_to_wif(self.disaster, Keytype.QDRECOVERYPUBKEY)

    def _owner_sign(self, data):
        """Sign the disastery recovery key with the ECDSA owner key"""
        ecdsa_signingkey = PrivateKey.fromString( hexlify(self.owner))
        sig =  ecdsa.Ecdsa.sign(data.decode("latin1"), ecdsa_signingkey)
        return sig.toDer(withRecoveryId=True)

    def update_account_json(self):
        """Store the OWNER-key ECDSA signed disaster recovery pubkey on as HIVE account JSON metadata"""
        account_obj = json.loads(self.client.get_accounts([self.username])[0]["json_metadata"])
        pubkey = self._disaster_pubkey()
        sig = self._owner_sign(pubkey)
        keyinfo = {}
        keyinfo["key"] = key_to_wif(pubkey, Keytype.QDRECOVERYPUBKEY)
        keyinfo["sig"] = b58encode(sig).decode("latin1")
        account_obj["coinzdense_disaster_recovery"] = keyinfo
        newjson = json.dumps(account_obj)
        active = key_to_wif(self.active, Keytype.ECDSAPRIVKEY)
        clnt = Client(keys=[active])
        ops = [
            Operation('account_update',
                      {
                        'account': self.username,
                        'json_metadata': newjson
                      }
                     )
        ]
        clnt.broadcast(ops)

def main():
    """Temporary one-function main, needs to implement subcommands soon"""
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
