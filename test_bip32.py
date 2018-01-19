
# --- Usage and testing BIP32 ---
if __name__ == "__main__":

    import os.path
    from btc.keys import KeysBTC
    from btc.bip39 import BIP39
    from btc.bip32 import ExtendedKey, BIP32

    # check url: https://iancoleman.io/bip39/
    bip39 = BIP39(
        os.path.join(os.path.dirname(os.path.realpath(__file__)),
                     'english.txt')
    )
    seed = bip39.mnemonic_to_seed(
        "people glad express guilt humble maximum "
        "spike silly valley appear second feed".split(),
        ""
    )
    # Create an extended key
    root_prv = ExtendedKey.seed_to_master_key(seed)

    # BIP32 with m/44'/0'/0'
    bip32_1 = BIP32(
        root_prv,
        [BIP32.hardened_index(44),
         BIP32.hardened_index(0),
         BIP32.hardened_index(0)]   # path -- m/44'/0'/0'
    )

    # Master private
    print(bip32_1.master_prv.serialize())

    # Master public
    print(bip32_1.master_pub.serialize())

    # Child private keys with indexes in [0, 9] from parent private key
    child_prv = [
        KeysBTC.privatekey_to_wif(c.key)
            for c in bip32_1.ckd_priv(range(0, 10))
    ]
    print("Child private keys from the parent private m/44'/0'/0'/[0, 9]: ",
          dict(zip(range(0, 10), child_prv)) )

    # BIP32 with m/517/377/11
    root_pub = ExtendedKey(
        KeysBTC(root_prv.key).get_public_point(),
        root_prv.chain_code
    )
    bip32_2 = BIP32(root_pub, [517, 377, 11])   # path -- m/517/377/11

    # Child public keys from parent public key, only for non-hardened keys
    child_public = [
        KeysBTC.point_to_publickey(c.key).hex()
            for c in bip32_2.ckd_pub(range(0, 10))
    ]
    print("Child public keys from the parent public: ",
          dict(zip(range(0, 10), child_public)) )


    # Serialization
    # An extended private key deserialization and gen a child private key
    k = ExtendedKey(bytes(), bytes())
    k.deserialize("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP"
                  "qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    bip32 = BIP32(k)
    child_private = BIP32.prv_to_child(k, bip32.hardened_index(0))      # m/0'
    print(child_private.serialize())

    # An extended public key deserialization and gen a child public key
    k.deserialize("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUa"
                  "pSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
    child_public = BIP32.pub_to_child(k, 0)     # m/0
    print(child_public.serialize())

