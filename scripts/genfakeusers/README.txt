README for:  genfakeusers.py
Author: Calin Culianu <calin.culianu@gmail.com>

This script generates fake users for testnet. The payout addresses are real
and are from a testnet wallet with 5k change and 5k receiving addresses with
this BIP39 seed:

         BIP39 seed:    donkey pig blast merit minute law orient elder clinic midnight ball box
    derivation path:    m/44'/145'/0

After running the script, a directory logs/users will be populated with all
the addresses from addresses.json, using template.json as a template.

You may copy these files to your pool's logs/users in order to sumulate a 
pool with 10k+ users.  This is useful for load testing on testnet to see
how the software behaves when there are very many payouts and users.


