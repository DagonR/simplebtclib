
# --- Usage and testing ---
if __name__ == "__main__":

    from btc.utils import sha256
    from btc.keys import KeysBTC

    k = KeysBTC("96a69d6682a4b2eb522e896c2fa1b8ada485c472b983e27266d1d5c8c77ec374")

    # Check the right values at https://www.bitaddress.org
    # An object methods
    print("Private key (hex): ", k.get_private_key_hex())
    print("Private key (WIF-compressed): ", k.get_private_key_wif(True))
    print("Private key (WIF-uncompressed): ", k.get_private_key_wif(False))
    print("Public point: ", k.get_public_point())
    print("Public key (hex): ", k.get_public_key(compressed=True).hex(),)
    print("Is public key compressed: ", k.is_pubkey_compressed())
    print("Public key HASH160: ", k.get_pubkey_hash().hex())
    print("Address: ", k.get_address())

    # Static methods (convertions)
    print("Generator point: ", k.get_generator_point())
    print("Private key to WIF: ", k.privatekey_to_wif(k._private_key, compressed=False))
    print("WIF to private key", k.privatekey_from_wif(k.get_private_key_wif()).hex())
    print(k.address_to_pubkey_hash(k.get_address()).hex())

    # Sign and verify
    message = sha256(b"sample")
    r, s = k.sign(message)
    print(k.verify(message, r, s))



