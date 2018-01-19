
# --- Usage and testing BIP39 ---
if __name__ == "__main__":

    import os.path
    import json
    from btc.bip39 import BIP39

    bip39 = BIP39(
        os.path.join(os.path.dirname(os.path.realpath(__file__)),
                     'english.txt')
    )

    # Check the right values in vectors.json
    test_vectors = \
        json.load(
            open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'vectors.json'),
                 'r'
            )
        )

    for w in test_vectors["english"]:
        # get values
        ml = bip39.entropy_to_mnemonic(bytes.fromhex(w[0]))
        seed = bip39.mnemonic_to_seed(ml, "TREZOR")
        entropy = bip39.mnemonic_to_entropy(w[1].split())

        ok = (seed.hex() == w[2]) and \
             (" ".join(ml) == w[1]) and \
             (entropy.hex() == w[0])

        if not ok:
            print ("FALSE for: ", w[0])
        else:
            print ("OK", ml)
