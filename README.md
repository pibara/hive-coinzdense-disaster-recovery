# HIVE CoinZdense Disaster Recovery tools

This repo is currently a work in progress, nothing real to see here.

This is a spin-off of the [CoinZdense](https://pibara.github.io/coinzdense/) that was incepted as a result of discussions 
during [HiveFest 2022](https://hivefe.st/). The idea is to create a set of tools to place single hash-based-signing pubkey
into the account JSON on the chain signed with the user's owner key. That signed and timestamped key can than later serve as
proof of ownership for the account in an operation that replaced the ECDSA OWNER-key with a CoinZdense OWNER-key.

This is only a partial recovery plan, but one that could be implemented relatively quickly and could get integrated into new
account creation procedures.


