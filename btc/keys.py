from btc.utils import sha256, ripemd160, base58_encode, base58_decode, \
    mod_inverse, int2bytes, bytes2int
from btc.randoms import random_bbs, random_rfc6979
from btc.ecpoint import ECPoint


ADDRESS_PREFIX_MAINNET = 0x00
ADDRESS_PREFIX_TESTNET = 0x6f


class KeysBTC:
    """Represents basic Bitcoin cryptography operations.

     Getting keys and addresses, transforming formats, signing and verifying.
     """

    def __init__(self, private_key=None):
        """Construct an object with a private key (bytes or str)"""

        # Init private_key, if input is None then get a random BBS
        if private_key is None:
            self._private_key = int2bytes(
                random_bbs(ECPoint.get_secp256k1_order_len())
            )
        else:
            self._private_key = bytes.fromhex(private_key) \
                if isinstance(private_key, str) else private_key

        assert bytes2int(self._private_key) > 0, "Invalid private key"

        self._public_point = None
        self._public_key = None
        self._public_key_hash = None
        self._address = None


    def __repr__(self):
        return \
            str({
                "private_key": self._private_key.hex(),
                "public_key": self._public_key.hex() \
                    if self._public_key else None,
                "address": self._address
            })


    def get_private_key(self):
        return self._private_key


    def get_private_key_int(self):
        """Convert the object's private key to int"""
        return bytes2int(self._private_key)


    def get_private_key_hex(self):
        """Convert the object's private key to hex octets (str of 64 chars)"""
        return self.get_private_key().hex()


    def get_private_key_wif(self, compressed=True):
        """Return the object's private key in WIF"""
        return self.privatekey_to_wif(self._private_key, compressed)


    def get_public_point(self):
        """Return a public point on the elliptic curve"""
        if self._public_point is None:
            self._public_point = self.get_generator_point() * \
                                 self.get_private_key_int()

        return self._public_point


    def get_public_key(self, compressed=True):
        """Return bytes with the public key"""
        # If compressed then use only x coordinate (prefix 02 or 03)
        # of the public point else x and y coordinates (prefix 04).
        if self._public_key is None:
            self._public_key = \
                self.point_to_publickey(self.get_public_point(), compressed)

        return self._public_key


    def is_pubkey_compressed(self):
        """Return True if the object's public key is compressed"""
        self.get_public_key()
        # Check the public key's prefix
        if self._public_key[0] in [2, 3]:
            return True
        elif self._public_key[0] == 4:
            return False
        else:
            raise ValueError(
                "Invalid public key: {:s}".format(self._public_key.hex())
            )


    def get_pubkey_hash(self):
        """Return the object's public key hash"""
        if self._public_key_hash is None:
            self._public_key_hash = \
                ripemd160(sha256(self.get_public_key()))

        return self._public_key_hash


    def get_address(self, version: int=None):
        """Return the object's btc-address"""
        # If None then version is a mainnet address
        version = ADDRESS_PREFIX_MAINNET if version is None else version

        if self._address is None:
            # Set an address version (mainnet or testnet)
            t = bytes([version]) + self.get_pubkey_hash()
            # Add checksum
            t += sha256(sha256(t))[0:4]
            # Count leading zeros
            leading_zeros = 0
            for _ in t:
                if _ == 0:
                    leading_zeros += 1
                else:
                    break
            # Change leading zeros by ones and encode to base58
            self._address = leading_zeros * "1" + \
                            base58_encode(t)

        return self._address


    @staticmethod
    def get_generator_point():
        """Return Generator Point for SECP256k1"""
        return ECPoint(ECPoint.get_secp256k1_gx(),
                       ECPoint.get_secp256k1_gy())


    @staticmethod
    def privatekey_to_wif(private_key: bytes, compressed=True):
        """Convert a private key to WIF (str)"""
        compressed_flag = b"\x01" if compressed else b""
        wif = b"\x80" + private_key + compressed_flag
        double_sha = sha256(sha256(wif))
        try:
            return base58_encode(wif + double_sha[:4])
        except Exception:
            raise ValueError(
                "Invalid private key: {:s}".format(private_key.hex())
            )


    @staticmethod
    def privatekey_from_wif(wif: str):
        """Convert private key WIF to an integer"""
        try:
            p = base58_decode(wif, 38)
            return p[1:33]
        except Exception:
            raise ValueError(
                "Invalid private key in WIF: {:s}".format(wif)
            )


    @staticmethod
    def point_to_publickey(point: ECPoint, compressed = True):
        """Convert a point to a public key"""
        if compressed:
            return (b"\x02" if point.y % 2 == 0 else b"\x03") + \
                   int2bytes(point.x)
        else:
            return b"\x04" + int2bytes(point.x) + int2bytes(point.y)


    @staticmethod
    def address_to_pubkey_hash(address: str):
        """Check an address checksum.

        Return Public Key Hash if the checksum is correct
        else raise ValueError.
        """
        # calculate the public key hash
        t = base58_decode(address.lstrip("1"), 25)
        # If the checksum is correct
        if sha256(sha256(t[:21]))[:4] == t[21:]:
            return t[1:21]
        else:
            raise ValueError(
                "Incorrect checksum for address: {:s}".format(address)
            )


    @staticmethod
    def get_addr_ver_main():
        return ADDRESS_PREFIX_MAINNET


    @staticmethod
    def get_addr_ver_test():
        return ADDRESS_PREFIX_TESTNET


    def sign(self, hash: bytes):
        """Sign a hash with the object's keys"""
        private_key_int = self.get_private_key_int()
        N = ECPoint.get_secp256k1_order()
        h = bytes2int(hash) % N
        h = 1 if h == 0 else h

        # get the deterministic random integer with RFC 6979
        k = random_rfc6979(hash, private_key_int, N,
                           self.get_generator_point())
        # Calculate G * k
        C = self.get_generator_point() * k
        s = ((h + C.x * private_key_int) * mod_inverse(k, N)) % N

        # Return r and s
        return int2bytes(C.x), int2bytes(s)


    def verify(self, hash: bytes, r: bytes, s: bytes):
        """Verify a sign r, s for a hash with the object's keys"""
        N = ECPoint.get_secp256k1_order()
        h = bytes2int(hash) % N
        h = 1 if h == 0 else h

        r1 = bytes2int(r)
        s_inv = mod_inverse(bytes2int(s), N)
        u1 = (h * s_inv) % N
        u2 = (r1 * s_inv) % N
        C = self.get_generator_point() * u1 + self.get_public_point() * u2

        return C.x == r1
