# Simple Bitcoin Library (simplebtclib)

This Python3 library provides an object-oriented implementation of the basic Bitcoin 
structures: keys and transactions. The main purpose of the library is to facilitate 
understanding of the Bitcoin structures in a raw form, though it can be used for 
performing real Bitcoin transactions. Some algorithms and BIPs implemented in the 
library make it useful for educational purposes and dealing with cryptocurrencies.


### Requirements

No additional requirements.
The library uses just standard Python3 functions and classes.


### Structure

* utils: 
  * auxillary and type-conversion functions
* randoms: 
  * algorithm Blum-Blum-Shub - generating a random number
  * RFC 6979 - generating a random number
* ecpoint:
  * ECPoint - a point on an elliptic curve
* keys:
  * KeysBTC - getting Bitcoin keys and addresses, transforming key formats, signing and verifying
* transact:
  * TransactBTC - forming and signing Bitcoin transactions
* bip32:
  * ExtendedKey - an extended key (+chain) from BIP0032
  * BIP32 - a hierarchy of deterministic keys from BIP0032
* bip39:
  * BIP39 - a mnemonic code (sentence) for the generation of deterministic wallets (BIP0039)


## Test

Use test_\*.py modules from the library root.


### Usage

 * Generate keys:
```python
keys_from = KeysBTC()
keys_from.get_address()
print(keys_from)

```

 * Generate a transaction:
```python
keys_from = KeysBTC(private_key) # private key in str-hex format
tx = TransactBTC(keys_from)
tx.add_in_transaction(previous_tx_hash, output_num, keys_from)
tx.add_out_transaction(address1, value, "p2pkh")
tx.add_out_transaction(address2, value, "p2sh")
tx.sign_all_inputs()
print(tx)
```

       
## Built With

* [PyCharm Community](https://www.jetbrains.com/pycharm/)


## Author

**DagonR**


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.


## Acknowledgments
  * [BlockCypher](https://www.blockcypher.com) - Blockchain Web Services
  * [Bitcoin TestNet Sandbox](https://testnet.manu.backend.hamburg)

## References
  * ["Bitcoin: A Peer-to-Peer Electronic Cash System" by Satoshi Nakamoto](https://bitcoin.org/bitcoin.pdf)
  * [Bitcoin wiki](https://en.bitcoin.it/wiki/Main_Page)
  * ["Mastering Bitcoin" by Andreas M. Antonopoulos](http://chimera.labs.oreilly.com/books/1234000001802/ch01.html#_getting_started)
  * [Bitcoin in a nutshell by Pavlov_dog](https://habrahabr.ru/post/319868/)
  * [Bitcoin Developer Guide](https://bitcoin.org/en/developer-guide)
  * [JavaScript Client-Side Bitcoin Wallet Generator](https://www.bitaddress.org)
  * [Mnemonic Code Converter](https://iancoleman.io/bip39/)

