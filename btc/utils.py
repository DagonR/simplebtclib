from math import ceil
from random import randrange
import hashlib
import hmac


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_COUNT = len(BASE58_ALPHABET)


def base58_encode(b: bytes):
    """Encode a bytes-string to a base58-encoded string"""
    num = bytes2int(b)

    encoded = ""
    while num >= BASE58_COUNT:
        mod = num % BASE58_COUNT
        encoded = BASE58_ALPHABET[mod] + encoded
        num = num // BASE58_COUNT

    if num:
        encoded = BASE58_ALPHABET[num] + encoded

    return encoded


def base58_decode(s: str, length=None):
    """Decode a base58-encoded string to a bytes-string"""
    decoded = 0
    multi = 1
    s = s[::-1]

    for char in s:
        decoded += multi * BASE58_ALPHABET.index(char)
        multi = multi * BASE58_COUNT

    return int2bytes(decoded, length)


def sha(data: bytes, type="256"):
    """Return the hash bytes for data bytes"""
    if type == "1":
        hash = hashlib.sha1(data)
    elif type == "224":
        hash = hashlib.sha224(data)
    elif type == "256":
        hash = hashlib.sha256(data)
    elif type == "384":
        hash = hashlib.sha384(data)
    elif type == "512":
        hash = hashlib.sha512(data)
    else:
        raise ValueError("Invalid type for SHA")

    return hash.digest()


def hmac_sha(secret: bytes, data: bytes, type="256"):
    """Return the HMAC bytes for a couple of bytes (secret+data)"""
    if type  == "1":
        hash = hmac.new(secret, data, hashlib.sha1)
    elif type == "224":
        hash = hmac.new(secret, data, hashlib.sha224)
    elif type == "256":
        hash = hmac.new(secret, data, hashlib.sha256)
    elif type == "384":
        hash = hmac.new(secret, data, hashlib.sha384)
    elif type == "512":
        hash = hmac.new(secret, data, hashlib.sha512)
    else:
        raise ValueError("Invalid type for HMAC_SHA")

    return hash.digest()


def sha256(data):
    """Return the hash-sha256 (bytes/str) for data (bytes/str)"""
    if isinstance(data, str):
        return sha(bytes.fromhex(data), "256").hex()
    elif isinstance(data, bytes):
        return sha(data, "256")
    else:
        raise ValueError("Invalid type of parameters: {:s}", type(data))


def hmac_sha512(secret, data):
    """Return the hash HMAC-sha512 (bytes) for a couple secret+data"""
    return hmac_sha(secret, data, "512")


def ripemd160(data: bytes):
    """Return the hash160 (bytes) for bytes"""
    hash = hashlib.new("ripemd160")
    hash.update(data)
    return hash.digest()


def mod_inverse(a, m):
    """Return a^-1 mod m (modular inverse)"""

    def egcd(a, b):
        """Return an extended greatest common divisor for a, b"""
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - y*(b // a), y

    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse for: a={:d}, m={:d}".format(a, m))

    return x % m


def int2bytes(i: int, length=32):
    """Convert an integer to bytes of length"""
    if length is None:
        # if None then use the least possible length
        length = ceil(i.bit_length() / 8)

    return i.to_bytes(length, byteorder="big")


def bytes2int(b: bytes):
    """Convert a bytes (a sequence of bits) to an integer"""
    return int.from_bytes(b, byteorder="big", signed=False)


def int2hex(i: int, length=64):
    """Convert an integer to a sequence hex-octets (str) of length chars"""
    if length is None:
        # if None then use the least possible length
        length = ceil(i.bit_length() / 4)

    return "{:x}".format(i).zfill(length)


def hex2int(s: str):
    """Convert a hex-octets (a sequence of octets) to an integer"""
    return int(s, 16)


def gen_hex(length=64):
    """Return a random sequence of hex-octets"""
    return "".join(["{:x}".format(randrange(16)) for x in range(length)])


def signature_to_der(left: bytes, right: bytes):
    """Convert two integers (in sequences of bits) to
    Distinguished Encoding Rules (DER)
    """

    # Add a leading zero if the first bit is 1 (it must be a positive integer)
    r = b"\x00" + left if left[0] > 127 else left
    s = b"\x00" + right if right[0] > 127 else right

    # Add the prefix of an integer
    rs = b"\x02" + int2bytes(len(r), 1) + r + \
         b"\x02" + int2bytes(len(s), 1) + s

    # Add the prefix of sequence
    result = b"\x30" + int2bytes(len(rs), 1) + rs
    return result


def der_to_signature(der: bytes):
    """Convert a DER (two integers) to a list with two integers (in sequences of bits)"""
    #rs_len = der[1]
    r_len = der[3]
    s_len = der[5+r_len]

    r = der[4 : 4+r_len]
    # Del leading zero
    r = r[1:] if r[0] == 0 and r[1] > 127 else r

    s = der[6+r_len : 6+r_len+s_len]
    # Del leading zero
    s = s[1:] if s[0] == 0 and s[1] > 127 else s
    return r, s


def ipv42bytes(ipv4: str):
    """Convert IPv4 address to bytes (a sequence of bits)"""
    return bytes(map(int, ipv4.split('.')))


def bytes2ipv4(ipv4: bytes):
    """Convert a bytes (a sequence of bits) to IPv4 address"""
    return ".".join(str(b) for b in ipv4)
