# HIVE CoinZdense Disaster Recovery tools

The HIVE CoinZdense Disaster Recovery tools is a set of commandline tools for preparing your HIVE account for possible future disaster recovery in case of a succesfull quantum computing atack against the blockchain. It does this by publishing a hash based singing public key into the users meta data json that is (by default) derived from the users master password.

You need to run this tool only once to prepare your account for potential future disaster recovery. 

First do a pip install
```
python3 -m pip install hiveqdpr
```
If you still have your master password, call:
```
hqpdr-userpost-masterpass myhiveaccount
```
If instead you only have your owner key and your active key call:
```
hqpdr-userpost-randomkey myhiveaccount
```


For more info check this two part blog post:
* [part 1](https://peakd.com/hive-139531/@pibara/what-if-coinzdense-comes-to-late-a-little-unfinished-just-in-case-tool-for-preparing-for-quantum-event-disaster-recovery)
* [part 2](https://peakd.com/hive-139531/@pibara/what-if-coinzdense-comes-too-late-part-2--a-working-tool-for-preparing-for-quantum-disaster-recovery)

