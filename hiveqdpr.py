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
from libnacl import crypto_kdf_keygen as _nacl2_keygen
from libnacl import crypto_kdf_derive_from_key as _nacl2_key_derive
from nacl.hash import blake2b as _nacl1_hash_function
from nacl.encoding import RawEncoder as _Nacl1RawEncoder
import bip39
from lighthive.client import Client
from lighthive.datastructures import Operation
from base58 import b58encode, b58decode

# START OF COINZDENSE CODE
def _ots_pairs_per_signature(hashlen, otsbits):
    """Calculate the number of one-time-signature private-key up-down duos needed to
    sign a single digest"""
    return ((hashlen*8-1) // otsbits)+1

class OneTimeSigningKey:
    """Signing key for making a single one-time signature with"""
    # pylint: disable=too-many-arguments
    def __init__(self, hashlen, otsbits, levelsalt, key, startno, pubkey=None):
        """Constructor"""
        self._hashlen = hashlen
        self._otsbits = otsbits
        self._levelsalt = levelsalt
        self._pubkey = pubkey
        self._privkey = []
        self._chopcount = _ots_pairs_per_signature(hashlen, otsbits)
        # We use up one chunk of entropy for a nonce. This nonce is basically the
        #  salt we use instead of the level salt when hashing the transaction, message
        #  or next-level level-key pubkey.
        self._nonce = _nacl2_key_derive(hashlen,
                                        startno,
                                        "SigNonce",
                                        key)
        # Derive the whole one-time-signing private key from the seeding key.
        for keyspace_index in range(startno + 1, startno + 1 + 2 * self._chopcount):
            self._privkey.append(
                    _nacl2_key_derive(hashlen,
                                      keyspace_index,
                                      "Signatur",
                                      key)
                    )

    def get_pubkey(self):
        """Get the binary public key, calculate if needed.

        Returns
        -------
        bytes
            The public key.
        """
        if self._pubkey is None:
            pubparts = []
            # Calculate the full-sized one-time-signing pubkey
            for privpart in self._privkey:
                res = privpart
                # Calculate one chunk of the full-sized one-time-signing pubkey
                for _ in range(0, 1 << self._otsbits):
                    res = _nacl1_hash_function(res,
                                               digest_size=self._hashlen,
                                               key=self._levelsalt,
                                               encoder=_Nacl1RawEncoder)
                pubparts.append(res)
            # Calculate the normal-sized one-time-signing pubkey
            pubkey_long = b"".join(pubparts)
            self._pubkey = _nacl1_hash_function(
                    pubkey_long,
                    digest_size=self._hashlen,
                    key=self._levelsalt,
                    encoder=_Nacl1RawEncoder)
        return self._pubkey
    def sign_hash(self, digest):
        """Signature from hash

        Parameters
        ----------
        digest : bytes
            Hash of the data that needs signing

        Returns
        -------
        bytes
            The signature including nonce.

        Raises
        ------
        RuntimeError
            Thrown if digest has the wrong length
        """
        if len(digest) != self._hashlen:
            raise RuntimeError("sign_hash called with hash of inapropriate size")
        # Convert the input digest into an array of otsbits long numbers
        as_bigno = int.from_bytes(digest,
                                  byteorder='big',
                                  signed=True)
        as_int_list = []
        for _ in range(0, self._chopcount):
            as_int_list.append(as_bigno % (1 << self._otsbits))
            as_bigno = as_bigno >> self._otsbits
        as_int_list.reverse()
        # Make a convenience array, grouping the digest based numbers with the private key chunks
        my_sigparts = [
            [
                as_int_list[i//2],
                self._privkey[i],
                self._privkey[i+1]
            ] for i in range(0, len(self._privkey), 2)
        ]
        signature = b""
        for sigpart in my_sigparts:
            # Figure out the number of times the up and the down chain will need to repeat hashing
            # in order to create signature chunks.
            count1 = sigpart[0] + 1
            count2 = (1 << self._otsbits) - sigpart[0]
            # Hash the up-chain
            sig1 = sigpart[1]
            for _ in range(0, count1):
                sig1 = _nacl1_hash_function(
                           sig1,
                           digest_size=self._hashlen,
                           key=self._levelsalt,
                           encoder=_Nacl1RawEncoder)
            signature += sig1
            # Hash the down chain
            sig2 = sigpart[2]
            for _ in range(0, count2):
                sig2 = _nacl1_hash_function(
                        sig2,
                        digest_size=self._hashlen,
                        key=self._levelsalt,
                        encoder=_Nacl1RawEncoder)
            signature += sig2
        return signature
    def sign_data(self, data):
        """Signature from data

        Parameters
        ----------
        data : bytes
            Data that needs signing

        Returns
        -------
        bytes
            The signature including nonce.
        """
        # Hash the data, using the nonce salt as a key.
        digest = _nacl1_hash_function(
                        data,
                        digest_size=self._hashlen,
                        key=self._nonce,
                        encoder=_Nacl1RawEncoder)
        # Prefix the signature with the nonce
        return self._nonce + self.sign_hash(digest)

class OneTimeValidator:
    """Validator for one-time signature"""
    def __init__(self, hashlen, otsbits, levelsalt, otpubkey):
        """Constructor"""
        self._hashlen = hashlen
        self._otsbits = otsbits
        self._levelsalt = levelsalt
        self._pubkey = otpubkey
        self._chopcount = _ots_pairs_per_signature(hashlen, otsbits)

    def validate_hash(self, digest, signature):
        """Validate signature from signature

        Parameters
        ----------
        digest : bytes
                 Digest of the signed data
        signature : bytes
                      The signature including nonce, signing the data.

        Returns
        -------
        bool
            Boolean indicating if signature matches the pubkey/data combo

        Raises
        ------
        RuntimeError
            Thrown if digest or the signature has the wrong length
        """
        if len(digest) != self._hashlen:
            raise RuntimeError("sign_hash called with hash of inapropriate size")
        if len(signature) != self._hashlen * 2 * _ots_pairs_per_signature(
                self._hashlen,
                self._otsbits):
            raise RuntimeError("sign_hash called with signature of inapropriate size")
        # Chop up the signature into hashlen long chunks
        partials = [signature[i:i+self._hashlen] for i in range(0, len(signature), self._hashlen)]
        # Convert the input digest into an array of otsbits long numbers
        as_bigno = int.from_bytes(digest,
                                  byteorder='big',
                                  signed=True)
        as_int_list = []
        for _ in range(0, self._chopcount):
            as_int_list.append(as_bigno % (1 << self._otsbits))
            as_bigno = as_bigno >> self._otsbits
        as_int_list.reverse()
        # Make a convenience array, grouping the digest based numbers with the private key chunks
        my_sigparts = [
            [
                as_int_list[i//2],
                partials[i],
                partials[i+1]
            ] for i in range(0, len(partials), 2)
        ]
        # Complete the OTS chains to recover the full-sized OTS public key
        bigpubkey = b""
        for sigpart in my_sigparts:
            # Determine the amount of times we need to still hash to get at the pubkey chunk
            count1 = (1 << self._otsbits) - sigpart[0] - 1
            count2 = sigpart[0]
            # Complete the up-chain
            sig1 = sigpart[1]
            for _ in range(0, count1):
                sig1 = _nacl1_hash_function(
                           sig1,
                           digest_size=self._hashlen,
                           key=self._levelsalt,
                           encoder=_Nacl1RawEncoder)
            bigpubkey += sig1
            # Complete the down-chain
            sig2 = sigpart[2]
            for _ in range(0, count2):
                sig2 = _nacl1_hash_function(
                        sig2,
                        digest_size=self._hashlen,
                        key=self._levelsalt,
                        encoder=_Nacl1RawEncoder)
            bigpubkey += sig2
        # Convert the full-sized pubkey into the external pubkey.
        reconstructed_pubkey =  _nacl1_hash_function(
                                    bigpubkey,
                                    digest_size=self._hashlen,
                                    key=self._levelsalt,
                                    encoder=_Nacl1RawEncoder)
        # Check if the reconstructed pubkey matches the known pubkey
        return self._pubkey == reconstructed_pubkey

    def validate_data(self, data, signature):
        """Validate signature from data

        Parameters
        ----------
        data : bytes
                 The signed data
        signature : bytes
                      The signature including nonce, signing the data.

        Returns
        -------
        bool
            Boolean indicating if signature matches the pubkey/data combo
        """
        # Extract the nonce from the signature
        nonce = signature[:self._hashlen]
        # Hash the data using the nonce
        digest = _nacl1_hash_function(
                        data,
                        digest_size=self._hashlen,
                        key=nonce,
                        encoder=_Nacl1RawEncoder)
        # Validate the resulting digest is indeed signed with the known OTS key.
        return self.validate_hash(digest, signature[self._hashlen:])

# END OF COINZDENSE CODE


# START OF CODE THAT NEEDS MINOR REFACTOR TO BE MADE PART OF COINZDENSE
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

def wif_to_binary(wif, expectedtype):
    """Restore binary key from WIF

    Parameters
    ----------
    wif : string
        wif base58 encoded key
    expectedtype : Keytype
        expected type of Wif encoded key

    Returns
    -------
    bytes
        The binary key

    Raises
    ------
    RuntimeError
        Thrown if WIF not of right type.
    """
    prefixmap = {
        "QRK": Keytype.QDRECOVERYPUBKEY,
        "CZD": Keytype.COINZDENSEPUBKEY,
        "STM": Keytype.ECDSACOMPRESSEDPUBKEY
    }
    netmap = {
        b'\xbb': Keytype.QDRECOVERYPRIVKEY,
        b'\xbd': Keytype.COINZDENSEPRIVKEY,
        b'\x80': Keytype.ECDSAPRIVKEY
    }
    if wif[:3] in prefixmap:
        keytype = prefixmap[wif[:3]]
        binkey = b58decode(wif[3:])[:-4]
    else:
        binwif = b58decode(wif)
        binkey = binwif[1:-4]
        if binwif[0:1] in netmap:
            keytype = netmap[binwif[0:1]]
        else:
            print(wif, expectedtype, hexlify(binwif), binwif[0:1], netmap)
            raise RuntimeError("Invalid input WIF")
    if keytype != expectedtype:
        raise RuntimeError("WIF of incorrect type")
    recalculated = key_to_wif(binkey, keytype)
    # pylint: disable=consider-using-assignment-expr
    if recalculated != wif:
        raise RuntimeError("Invalid input WIF")
    return binkey

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

# END OF CODE THAT NEEDS MINOR REFACTOR TO BE MADE PART OF COINZDENSE

def check_role_wif(client, username, wif, role):
    activekey = PrivateKey.fromString(hexlify(wif_to_binary(wif, Keytype.ECDSAPRIVKEY)))
    b58key = key_to_wif(pubkey_to_compressed(activekey.publicKey()), Keytype.ECDSACOMPRESSEDPUBKEY)
    account_infos = client.get_accounts([username])
    for accountinfo in account_infos:
        if role in accountinfo:
            rinfo = accountinfo[role]
            if 'key_auths' in rinfo:
                for auth in rinfo['key_auths']:
                    if auth[0] == b58key:
                        return
    raise RuntimeError("Not the " + role + " key for " + username)

class HiveAccount:
    """Class representing HIVE account."""
    def __init__(self, username, password=None, ownerwif=None, activewif=None, wif=None):
        """Constructor"""
        self.scope = "disaster"
        self.keylen = 24
        self.otsbits = 12
        self.username = username
        self.client = Client()
        if ownerwif is None:
            if activewif is None:
                self.owner = key_from_creds(username, "owner", password)
            else:
                self.owner = None
        else:
            check_role_wif(self.client, username, ownerwif, "owner")
            self.owner = wif_to_binary(ownerwif, Keytype.ECDSAPRIVKEY)
        if activewif is None:
            self.active = key_from_creds(username, "active", password)
        else:
            check_role_wif(self.client, username, activewif, "active")
            self.active = wif_to_binary(activewif, Keytype.ECDSAPRIVKEY)
        if password is not None:
            self.disaster = key_from_creds(username, self.scope, password)
        else:
            self.disaster = wif_to_binary(wif, Keytype.QDRECOVERYPRIVKEY)
        activekey = PrivateKey.fromString(hexlify(self.active))
        b58key = key_to_wif(pubkey_to_compressed(activekey.publicKey()), Keytype.ECDSACOMPRESSEDPUBKEY)
        keyrefs = self.client.get_key_references([b58key])
        if not keyrefs[0] or keyrefs[0][0] != username:
            print(keyrefs, username)
            raise RuntimeError("ERROR: User and password don't match with HIVE account.")
    def _disaster_pubkey(self):
        """Derive the binary disaster recovery pubkey from the binary private key"""
        # Derive a salt for hashing operations from the private key
        hashing_salt = _nacl2_key_derive(self.keylen, 0, self.scope, self.disaster)
        otsk = OneTimeSigningKey(self.keylen, self.otsbits, hashing_salt, self.disaster, 1)
        return otsk.get_pubkey()

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

    def _active_sign(self, data):
        """Sign the disastery recovery key with the ECDSA owner key"""
        ecdsa_signingkey = PrivateKey.fromString( hexlify(self.active))
        sig =  ecdsa.Ecdsa.sign(data.decode("latin1"), ecdsa_signingkey)
        return sig.toDer(withRecoveryId=True)

    def update_account_json(self):
        """Store the OWNER-key ECDSA signed disaster recovery pubkey on as HIVE account JSON metadata"""
        account_obj = json.loads(self.client.get_accounts([self.username])[0]["json_metadata"])
        if "coinzdense_disaster_recovery" not in account_obj:
            account_obj["coinzdense_disaster_recovery"] = {}
        pubkey = self._disaster_pubkey()
        if self.owner is not None:
            sig = self._owner_sign(pubkey)
            account_obj["coinzdense_disaster_recovery"]["key"] = key_to_wif(pubkey, Keytype.QDRECOVERYPUBKEY)
            account_obj["coinzdense_disaster_recovery"]["sig"] = b58encode(sig).decode("latin1")
        else:
            sig = self._active_sign(pubkey)
            account_obj["coinzdense_disaster_recovery"]["key-a"] = key_to_wif(pubkey, Keytype.QDRECOVERYPUBKEY)
            account_obj["coinzdense_disaster_recovery"]["sig-a"] = b58encode(sig).decode("latin1")
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

def _main_userpost_masterpass():
    """Main for publishing a HIVE master-password-derived disaster-recovery key as account meta."""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    password = getpass("Password for " + username + ": ")
    account = HiveAccount(username, password=password)
    account.update_account_json()
    print("Registered disaster recovery key")

def _main_userpost_altpass():
    """Main for publishing an alternate-password-derived disaster-recovery key as account meta."""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    password = getpass("Password : ")
    owner = getpass("Owner Key (press enter if you don't have one): ")
    if owner == "":
        owner=None
    active = getpass("Active key : ")
    account = HiveAccount(username, password=password, ownerwif=owner, activewif=active)
    account.update_account_json()
    print("Registered disaster recovery key")

def _main_userpost_randomkey():
    """Main for publishing a new randomly created disaster-recovery key as account meta."""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    wif = key_to_wif(_nacl2_keygen(), Keytype.QDRECOVERYPRIVKEY)
    print("New disaster recovery key :", wif)
    owner = getpass("Owner Key (press enter if you don't have one): ")
    if owner=="":
        owner=None
    active = getpass("Active key : ")
    account = HiveAccount(username, wif=wif, ownerwif=owner, activewif=active)
    account.update_account_json()
    print("Registered disaster recovery key")
    print("Make sure to store the new disaster recovery key somewhere safe")

def _main_userpost_wif():
    """Main for publishing an existing disaster-recovery key as account meta."""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    wif = getpass("Disaster-Recovery Key : ")
    owner = getpass("Owner Key (press enter if you don't have one): ")
    if owner=="":
        owner=None
    active = getpass("Active key : ")
    account = HiveAccount(username, wif=wif, ownerwif=owner, activewif=active)
    account.update_account_json()
    print("Registered disaster recovery key")

def _main_userverify_ecdsa():
    """Main for ECDSA check of published disaster-recovery key"""
    print("ERROR: Not yet implemented")

def _main_disasterkey_pass():
    """Main for getting the private disaster recovery key from the master password without network interaction"""
    print("ERROR: Not yet implemented")

def _main_disasterkey_bip38():
    """Main for restoring the private disaster recovery key from bip38 word list"""
    print("ERROR: Not yet implemented")

def _main_bip38_wif():
    """Main for turning the private disaster recovery key into a bip38 word list"""
    print("ERROR: Not yet implemented")

def _main_bip38_masterpass():
    """Main for getting the bip38 word list of the private disaster recovery key from the master password"""
    print("ERROR: Not yet implemented")

def _main_sign_pass():
    """Main to sign a hex encoded binary object with private disaster recovery key using the master password"""
    print("ERROR: Not yet implemented")

def _main_sign_wif():
    """Main to sign a hex encoded binary object with private disaster recovery key using Wif"""
    print("ERROR: Not yet implemented")

def _main_sign_bip38():
    """Main to sign a hex encoded binary object with private disaster recovery key using bip38 wordlist"""
    print("ERROR: Not yet implemented")

def _main_validate():
    """Main to validate a private disaster recovery key signed hex encoded binary object."""
    print("ERROR: Not yet implemented")

if __name__ == "__main__":
    _main_userpost_masterpass()
