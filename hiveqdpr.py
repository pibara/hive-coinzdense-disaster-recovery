#!/usr/bin/python3
"""Tool for handling hash-based one time disastery recovery keys for HIVE"""
import json
import sys
from sys import argv
import base64
from getpass import getpass
from binascii import hexlify
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve import ecdsa
from ellipticcurve import signature as ecdsasignature
from libnacl import crypto_kdf_keygen as _nacl2_keygen
from libnacl import crypto_kdf_derive_from_key as _nacl2_key_derive
from nacl.hash import blake2b as _nacl1_hash_function
from nacl.encoding import RawEncoder as _Nacl1RawEncoder
from lighthive.client import Client
from lighthive.datastructures import Operation
from base58 import b58encode, b58decode
from coinzdense.layerzero.onetime import OneTimeSigningKey, OneTimeValidator
from coinzdense.layerzero.wif import Keytype, binary_to_wif, wif_to_binary, pubkey_to_compressed, compressed_to_pubkey, key_from_creds


def _ots_pairs_per_signature(hashlen, otsbits):
    """Calculate the number of one-time-signature private-key up-down duos needed to
    sign a single digest"""
    return ((hashlen*8-1) // otsbits)+1

def parameterized_coinzdense_pubkey(account, password, hashlen, otsbits, l0height):
    """Calculate a possible CoinZdense pubkey given parameters

    Parameters
    ----------
    account : string
        HIVE account name
    password : string
        HIVE master password or alt password
    hashlen : int
        The hash lengt uses throughout the hash-based signing implementation
    otsbits : int
        The number of bits encoded per up/down set of OTS chains
    l0height : int
        Merkle tree height for the level zero level key

    Returns
    -------
    string
        WIF encoded CoinZdense pubkey
    """
    seedkey = key_from_creds(account, "czdowner", password)
    otscount = 1 << l0height
    levelsalt = _nacl2_key_derive(hashlen, 0, "levelslt", seedkey)
    entropy_per_signature = _ots_pairs_per_signature(hashlen, otsbits) + 2 # nonce plus spare nonce
    next_index = 1
    ots_pubkeys = []
    for _ in range(0, otscount):
        otsk = OneTimeSigningKey(hashlen, otsbits, levelsalt, seedkey, next_index)
        ots_pubkeys.append(otsk.get_pubkey())
        next_index += entropy_per_signature
    # pylint: disable=while-used
    while len(ots_pubkeys) > 1:
        ots_pubkeys = [_nacl1_hash_function(ots_pubkeys[i] + ots_pubkeys[i+1],
                                            digest_size=hashlen,
                                            key=levelsalt,
                                            encoder=_Nacl1RawEncoder) for i in range(0, len(ots_pubkeys),2)]
    return binary_to_wif(ots_pubkeys[0], Keytype.COINZDENSEPUBKEY)

def check_role_wif(client, username, wif, role):
    """Check if this WIF actually belongs to the user under the given role

    Parameters
    ----------
    client : lighthive.client.Client
               HIVE client
    username : string
                 HIVE account name
    wif : string
            HIVE private key WIF
    role : string
            NAME of the HIVE role belonging with this WIF

    Raises
    ------

    RuntimeError
        Raised if the role/user don't match the WIF
    """
    activekey = PrivateKey.fromString(hexlify(wif_to_binary(wif, Keytype.ECDSAPRIVKEY)))
    b58key = binary_to_wif(pubkey_to_compressed(activekey.publicKey()), Keytype.ECDSACOMPRESSEDPUBKEY)
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
        b58key = binary_to_wif(pubkey_to_compressed(activekey.publicKey()), Keytype.ECDSACOMPRESSEDPUBKEY)
        keyrefs = self.client.get_key_references([b58key])
        if not keyrefs[0] or keyrefs[0][0] != username:
            raise RuntimeError("ERROR: User and password don't match with HIVE account.")
    def _disaster_pubkey(self):
        """Derive the binary disaster recovery pubkey from the binary private key"""
        # Derive a salt for hashing operations from the private key
        hashing_salt = _nacl2_key_derive(self.keylen, 0, "levelslt", self.disaster)
        otsk = OneTimeSigningKey(self.keylen, self.otsbits, hashing_salt, self.disaster, 1)
        return otsk.get_pubkey()

    def get_privkey(self):
        """Get disaster recovery privkey as WIF

        Returns
        -------
        string
            Base58 representation of the disaster recovery private key.
        """
        return binary_to_wif(self.disaster, Keytype.QDRECOVERYPRIVKEY)

    def get_pubkey(self):
        """Get the public recovery key

        Returns
        -------
        sting
            WIF formatted b58 recovery pubkey
        """
        return binary_to_wif(self._disaster_pubkey(), Keytype.QDRECOVERYPUBKEY)


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
        json_meta = self.client.get_accounts([self.username])[0]["json_metadata"]
        account_obj = json.loads(
                self.client.get_accounts([self.username])[0]["json_metadata"]
                ) if json_meta else {}
        if "coinzdense_disaster_recovery" not in account_obj:
            account_obj["coinzdense_disaster_recovery"] = {}
        pubkey = self._disaster_pubkey()
        if self.owner is not None:
            sig = self._owner_sign(pubkey)
            account_obj["coinzdense_disaster_recovery"]["key"] = binary_to_wif(pubkey, Keytype.QDRECOVERYPUBKEY)
            account_obj["coinzdense_disaster_recovery"]["sig"] = b58encode(sig).decode("latin1")
        else:
            sig = self._active_sign(pubkey)
            account_obj["coinzdense_disaster_recovery"]["key-a"] = binary_to_wif(pubkey, Keytype.QDRECOVERYPUBKEY)
            account_obj["coinzdense_disaster_recovery"]["sig-a"] = b58encode(sig).decode("latin1")
        newjson = json.dumps(account_obj)
        active = binary_to_wif(self.active, Keytype.ECDSAPRIVKEY)
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
    print("Registered disaster recovery key:", account.get_pubkey())

def _main_userpost_altpass():
    """Main for publishing an alternate-password-derived disaster-recovery key as account meta."""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    password = getpass("Password : ")
    owner = getpass("Owner Key (press enter if you don't have one): ")
    owner = owner if owner else None
    active = getpass("Active key : ")
    account = HiveAccount(username, password=password, ownerwif=owner, activewif=active)
    account.update_account_json()
    print("Registered disaster recovery key :", account.get_pubkey())

def _main_userpost_randomkey():
    """Main for publishing a new randomly created disaster-recovery key as account meta."""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    wif = binary_to_wif(_nacl2_keygen(), Keytype.QDRECOVERYPRIVKEY)
    print("New disaster recovery key :", wif)
    owner = getpass("Owner Key (press enter if you don't have one): ")
    owner = owner if owner else None
    active = getpass("Active key : ")
    account = HiveAccount(username, wif=wif, ownerwif=owner, activewif=active)
    account.update_account_json()
    print("Registered disaster recovery key: ", account.get_pubkey())
    print("Make sure to store the new disaster recovery key somewhere safe")

def _main_userpost_wif():
    """Main for publishing an existing disaster-recovery key as account meta."""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    wif = getpass("Disaster-Recovery Key : ")
    owner = getpass("Owner Key (press enter if you don't have one): ")
    owner = owner if owner else None
    active = getpass("Active key : ")
    account = HiveAccount(username, wif=wif, ownerwif=owner, activewif=active)
    account.update_account_json()
    print("Registered disaster recovery key:", account.get_pubkey())

def _userverify_ecdsa(rolename, roleinfo, key, sig):
    pubkeys = []
    if 'key_auths' in roleinfo:
        for auth in roleinfo['key_auths']:
            pubkeys.append(auth[0])
    binkey = wif_to_binary(key, Keytype.QDRECOVERYPUBKEY)
    binsig = b58decode(sig)
    for pubkey in pubkeys:
        pubkey2 = compressed_to_pubkey(wif_to_binary(pubkey, Keytype.ECDSACOMPRESSEDPUBKEY))
        sign = ecdsasignature.Signature.fromDer(binsig, recoveryByte=True)
        isok = ecdsa.Ecdsa.verify(binkey.decode("latin1"), sign, pubkey2)
        # pylint: disable=consider-using-assignment-expr
        if isok:
            print("Key", key, "was signed by accounts", rolename,"key")
            return True
    return False

def _main_userverify_ecdsa():
    """Main for ECDSA check of published disaster-recovery key"""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    client = Client()
    account_infos = client.get_accounts([username])
    # pylint: disable=consider-using-assignment-expr
    if not account_infos:
        print("ERROR: No such account")
        return
    account_info = account_infos[0]
    json_meta = account_info["json_metadata"]
    account_obj = json.loads(json_meta) if json_meta else {}
    if "coinzdense_disaster_recovery" not in account_obj:
        print("ERROR: No disaster recovery key registered for account")
        return
    drinfo = account_obj["coinzdense_disaster_recovery"]
    if "key" in drinfo and "sig" in drinfo:
        _userverify_ecdsa("OWNER", account_info["owner"], drinfo["key"], drinfo["sig"])
    if "key-a" in drinfo and "sig-a" in drinfo:
        _userverify_ecdsa("ACTIVE", account_info["active"], drinfo["key-a"], drinfo["sig-a"])

def _main_coinzdensepubkey():
    """Main for calculating coinzdense pubkey from username and password"""
    if len(argv) < 5:
        print("Please supply an account name, hashlength, otsbits and level-0 key height on the commandline")
        sys.exit(1)
    account = argv[1]
    hashlen = int(argv[2])
    otsbits = int(argv[3])
    l0height = int(argv[4])
    password = getpass("Password : ")
    seedkey = key_from_creds(account, "czdowner", password)
    print("Privkey:", binary_to_wif(seedkey,Keytype.COINZDENSEPRIVKEY))
    print("Pubkey :", parameterized_coinzdense_pubkey(account, password, hashlen, otsbits, l0height))

def _main_disasterkey_pass():
    """Main for getting the private disaster recovery key from the master password without network interaction"""
    if len(argv) < 2:
        print("Please supply an account name on the commandline")
        sys.exit(1)
    username = argv[1]
    password = getpass("Password : ")
    disaster = key_from_creds(username, "disaster", password)
    print("Recovery-Privkey:", binary_to_wif(disaster, Keytype.QDRECOVERYPRIVKEY))
    levelsalt = _nacl2_key_derive(24, 0, "levelslt", disaster)
    otskey = OneTimeSigningKey(24, 12, levelsalt, disaster, 1)
    print("Recovery-Pubkey:", binary_to_wif(otskey.get_pubkey(),Keytype.QDRECOVERYPUBKEY))


def _main_sign_wif():
    """Main to sign a hex encoded binary object with private disaster recovery key using Wif"""
    if len(argv) < 2:
        print("Please supply a coinzidense level-0 pubkey WIF on the commandline")
        sys.exit(1)
    coinzdensewif = argv[1]
    disasterwif = getpass("Disaster recovery privkey WIF : ")
    coinzdensekey = wif_to_binary(coinzdensewif, Keytype.COINZDENSEPUBKEY)
    disasterkey = wif_to_binary(disasterwif, Keytype.QDRECOVERYPRIVKEY)
    levelsalt = _nacl2_key_derive(24, 0, "levelslt", disasterkey)
    otskey = OneTimeSigningKey(24, 12, levelsalt, disasterkey, 1)
    signature = otskey.sign_data(coinzdensekey)
    print("Signature:")
    print(base64.b64encode(levelsalt + signature).decode("ascii"))
    print("Recovery-Pubkey:", binary_to_wif(otskey.get_pubkey(),Keytype.QDRECOVERYPUBKEY))

def _main_validate():
    """Main to validate a private disaster recovery key signed hex encoded binary object."""
    if len(argv) < 4:
        print("Please supply a coinzidense level-0 pubkey WIF, a recovery pubkey and a HB recovery signature on the commandline")
        sys.exit(1)
    coinzdensekey = wif_to_binary(argv[1], Keytype.COINZDENSEPUBKEY)
    disasterkey = wif_to_binary(argv[2], Keytype.QDRECOVERYPUBKEY)
    signature = base64.b64decode(argv[3])
    levelsalt = signature[:24]
    signature = signature[24:]
    validator = OneTimeValidator(24, 12, levelsalt, disasterkey)
    isok = validator.validate_data(coinzdensekey, signature)
    # pylint: disable=consider-using-assignment-expr
    if isok:
        print("Valid signature")
    else:
        print("ERROR: Invalid signature")
