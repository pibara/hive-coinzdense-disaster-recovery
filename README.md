# HIVE CoinZdense Disaster Recovery tools

This repo is currently a work in progress, nothing real to see here.

This is a spin-off of the [CoinZdense](https://pibara.github.io/coinzdense/) that was incepted as a result of discussions 
during [HiveFest 2022](https://hivefe.st/). The idea is to create a set of tools to place single hash-based-signing pubkey
into the account JSON on the chain signed with the user's owner key. That signed and timestamped key can than later serve as
proof of ownership for the account in an operation that replaced the ECDSA OWNER-key with a CoinZdense OWNER-key.

This is only a partial recovery plan, but one that could be implemented relatively quickly and could get integrated into new
account creation procedures.

# mpass-disaster.py

This script creates a disaster recovery key from the same master password that was used to create the OWNER/ACTIVE/POSTING key and registers it as account JSON content. Only the password needs to be supplied by the user.

```
$ ./mpass-disaster.py pibarabank
Password for pibarabank: 
Registered disaster recovery key
```

# opass-disaster.py (TODO)

This script creates a disaster recovery key from a different password than that that was used to create the OWNER/ACTIVE/POSTING.
The owner and active keys are supplied by the user, and the key and registers it as account JSON content.

# rkey-disaster.py (TODO)

Like opass-disaster.py, but disaster key is generated randomly instead of that it is derived from a password.

# sign-disaster.py (TODO)

Sign a hash-based replacement OWNER key

# validate-disaster (TODO)

Validate a signed hash-based replacement OWNER key

# hivecoinz (TODO)

Replacement script with subcommands
