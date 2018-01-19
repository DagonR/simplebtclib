from btc.utils import hmac_sha512, sha256, ripemd160, base58_encode, \
    base58_decode, int2bytes, bytes2int
from btc.ecpoint import ECPoint
from btc.keys import KeysBTC


MAINNET_PUBLIC = b"\x04\x88\xb2\x1e"
MAINNET_PRIVATE = b"\x04\x88\xad\xe4"
TESTNET_PUBLIC = b"\x04\x35\x87\xcf"
TESTNET_PRIVATE = b"\x04\x35\x83\x94"


class ExtendedKey:
    """Represents an extended private (k,c) or public key (K,c) (BIP32)"""

    def __init__(self, key, chain_code: bytes, level: int = 0,
                 index: int = 0, fingerprint: bytes = b"\x00\x00\x00\x00"):
        """Construct an object.

        Parameters:
            key -- bytes if an extended private key, an ECPoint if an extended
                   public key (left 32 bytes of HMAC-SHA512),
            chain_code -- a chain code (right 32 bytes of HMAC-SHA512),
            level -- a depth of the key,
            index -- an index of the key,
            fingerprint -- checksum for the parent public key.
        """
        self.key = key
        self.chain_code = chain_code
        self.level = level
        self.index = index
        self.fingerprint = fingerprint


    def __repr__(self):
        return \
            str({
                "key": self.key.hex()
                           if isinstance(self.key, bytes) else self.key,
                "chain_code": self.chain_code.hex(),
                "level": self.level,
                "index": self.index,
                "fingerprint": self.fingerprint.hex()
            })


    def is_public(self):
        """Return True if this is an extended public key"""
        return isinstance(self.key, ECPoint)


    def is_private(self):
        """Return True if this is an extended private key"""
        return isinstance(self.key, bytes)


    def serialize(self):
        """Return serialized format (str) of this key (xprv / xpub)"""
        if self.is_private():
            ser_key = (
                MAINNET_PRIVATE +
                int2bytes(self.level, 1) +
                self.fingerprint +
                int2bytes(self.index, 4) +
                self.chain_code +
                b"\x00" +
                self.key
            )
        elif self.is_public():
            ser_key = (
                MAINNET_PUBLIC +
                int2bytes(self.level, 1) +
                self.fingerprint +
                int2bytes(self.index, 4) +
                self.chain_code +
                KeysBTC.point_to_publickey(self.key)
            )
        else:
            raise ValueError("Invalid extended key")

        checksum = sha256(sha256(ser_key))[:4]

        return base58_encode(ser_key + checksum)


    def deserialize(self, ser_key: str):
        """Deserialize a serialized key into self"""
        ser_key = base58_decode(ser_key, 82)

        # Checksum
        if sha256(sha256(ser_key[:78]))[:4] != ser_key[78:]:
            raise ValueError(
                "Wrong checksum of the extended key: {:s}".format(ser_key.hex())
            )

        self.level = ser_key[4]
        self.fingerprint = ser_key[5:9]
        self.index = bytes2int(ser_key[9:13])
        self.chain_code = ser_key[13:45]

        if ser_key[:4] == MAINNET_PRIVATE:
            # Miss 00 and get the private key
            self.key = ser_key[46:78]
        elif ser_key[:4] == MAINNET_PUBLIC:
            # Get x coordinate of the public point
            x = bytes2int(ser_key[46:78])
            # Calculate y coordinate of the public point
            y = ECPoint.get_secp256k1_y(x)
            # Choice even y if prefix = 02, else choice odd y
            if ser_key[45] == 2:
                y = ECPoint.get_secp256k1_p() - y if y % 2 != 0 else y
            else:
                y = ECPoint.get_secp256k1_p() - y if y % 2 == 0 else y

            self.key = ECPoint(x, y)
        else:
            raise ValueError(
                "Invalid serialized extended key: {:s}".format(ser_key.hex())
            )


    @staticmethod
    def get_fingerprint(public_key):
        """Return first 4 bytes of HASH160 of the public_key"""
        return ripemd160(sha256(public_key))[:4]


    @staticmethod
    def seed_to_master_key(seed):
        """Return an extended master (root) private key (BIP32) for a seed"""
        hash = hmac_sha512(b"Bitcoin seed", seed)
        key = hash[:32]
        chain_code = hash[32:]

        # Check key
        key_int = bytes2int(key)
        if key_int == 0 or key_int >= ECPoint.get_secp256k1_order():
            raise ValueError("Wrong master key")

        return ExtendedKey(key, chain_code)


class BIP32:
    """Represents hierarchy deterministic keys BIP32"""

    def __init__(self, master: ExtendedKey, level_indexes=None):
        """Construct an object.

        Parameters:
        master -- an extended master (root) key (ExtendedKey)
        level_indexes -- a path to the last key level (list),
                         ex. for m/0/1/0/<list> - [0, 1, 0]
        """
        self.level_indexes = [] if level_indexes is None else level_indexes

        if master.is_private():
            self.master_prv = master
            self.master_pub = \
                ExtendedKey(
                    KeysBTC(self.master_prv.key).get_public_point(),
                    self.master_prv.chain_code
                )
        elif master.is_public():
            self.master_prv = None
            self.master_pub = master
        else:
            raise ValueError("Invalid master key: {:s}", master)


    @staticmethod
    def hardened_index(index):
        """Return a hardened key index for a key index"""
        return index + 2 ** 31


    @staticmethod
    def prv_to_child(parent_prv: ExtendedKey, index: int):
        """Return an extended child private key.

        Parameters:
            parent_prv -- a parent private key,
            index -- an index of a parent private key
        """
        cur_key = KeysBTC(parent_prv.key)
        ser32_index = int2bytes(index, 4)

        # If a hardened index the take the private key,
        # otherwise, take the public key.
        if index >= 2 ** 31:
            data = b"\x00" + cur_key.get_private_key() + ser32_index
        else:
            data = cur_key.get_public_key() + ser32_index

        child_hash = hmac_sha512(parent_prv.chain_code, data)

        child_hash_left = bytes2int(child_hash[:32])
        k_i = (child_hash_left + cur_key.get_private_key_int()) % \
              ECPoint.get_secp256k1_order()
        # Check the left part
        if child_hash_left >= ECPoint.get_secp256k1_order() or k_i == 0:
            raise ValueError("The resulting key is invalid")

        # The right part is child_hash[32:]
        return ExtendedKey(
            int2bytes(k_i),
            child_hash[32:],
            parent_prv.level + 1,    # increase level
            index,
            ExtendedKey.get_fingerprint(cur_key.get_public_key())
        )


    @staticmethod
    def pub_to_child(parent_pub: ExtendedKey, index: int):
        """Return an extended child public key.

        Parameters:
            parent_pub -- a parent public key,
            index -- an index of a parent public key
        """
        # Check if index is not a hardened key
        if index >= 2 ** 31:
            raise ValueError(
                "Cannot generate a child public key because "
                "it is a hardened key"
            )

        ser32_index = int2bytes(index, 4)
        public_key = KeysBTC.point_to_publickey(parent_pub.key)

        data = public_key + ser32_index

        child_hash = hmac_sha512(parent_pub.chain_code, data)

        child_hash_left = bytes2int(child_hash[:32])
        K_i = KeysBTC.get_generator_point() * child_hash_left + parent_pub.key
        # Check the left part
        if child_hash_left >= ECPoint.get_secp256k1_order() or \
                K_i == ECPoint.infinity():
            raise ValueError(
                "The resulting key is invalid for index {:d}".format(index)
            )

        # The right part is child_hash[32:]
        return ExtendedKey(
            K_i,
            child_hash[32:],
            parent_pub.level + 1,    # increase level
            index,
            ExtendedKey.get_fingerprint(public_key)
        )


    def build_keys_path(self, level_indexes = None):
        """Build a key chain to the last key level.

        Parameters:
            level_indexes -- a path to the last key level (list),
                             ex. for m/0/1/0/<list> - [0, 1, 0].
        """
        self.level_indexes = level_indexes \
            if level_indexes else self.level_indexes

        parent_prv = self.master_prv
        parent_pub = self.master_pub
        # keys_path -- the list with the couples of extended keys
        # {"private", "public"} for each level in level_indexes.
        #
        # The root is the couple of the master keys
        self.keys_path = [
            {"private": parent_prv,
             "public": parent_pub}
        ]

        # For each level calculate an apropriate key
        for level in range(0, len(self.level_indexes)):
            index = self.level_indexes[level]
            if not isinstance(index, int):
                raise ValueError("Wrong index in the list")

            # Calculate a child private key if the parent private key exists
            try:
                if parent_prv is not None:
                    parent_prv = self.prv_to_child(parent_prv, index)
            except ValueError as err:
                parent_prv = str(err)

            # Calculate a child public key if the parent public key exists
            try:
                if parent_pub is not None:
                    parent_pub = self.pub_to_child(parent_pub, index)
            except ValueError as err:
                parent_pub = str(err)

            self.keys_path.append(
                {"private": parent_prv,
                 "public": parent_pub}
            )
        return


    def ckd_priv(self, index_list):
        """Children key derivation (CKDpriv) from the master (root) private.

        Parameters:
            index_list -- a list with indexes for derivating child keys.
        Return -- a list with the extended private child keys (the last level).
        """
        self.build_keys_path()

        # Derivate child keys from the last key in the key_path
        return [
            self.prv_to_child(self.keys_path[-1]["private"], index)
                for index in index_list
        ]


    def ckd_pub(self, index_list):
        """Children key derivation (CKDpub) from the master (root) public.

        Parameters:
            index_list -- a list with indexes for derivating child keys.
        Return -- a list with the extended public child keys (the last level).
        """
        self.build_keys_path()

        # Derivate child keys from the last key in the key_path
        return [
            self.pub_to_child(self.keys_path[-1]["public"], index)
                for index in index_list
        ]

