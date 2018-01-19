from math import log2, gcd, ceil
from random import randrange, randint

from btc.utils import sha, hmac_sha
from btc.ecpoint import ECPoint


def is_prime(n, r=None):
    """Algorithm Miller-Rabin.

    Return True if n most probably is a prime number,
    r - number of rounds, recommended value = O(log2(n)).
    """

    def get_st(n):
        # Calculate s,t => n-1 = 2**s * t, where t is odd
        s, t = 0, n - 1

        while t % 2 == 0:
            s += 1
            t //= 2

        return s, t

    # If r is None then use recommended value = log2(n)
    r = ceil(log2(n)) if r is None else r
    # If n is even then it is not a prime
    if n <= 2 or n % 2 == 0:
        return False

    s, t = get_st(n)
    for k in range(r):
        a = randint(2, n - 2)
        x = pow(a, t, n)  # x = a**t mod n
        if x == 1 or x == n - 1:
            continue

        next_k = False
        for _ in range(s - 1):
            x = pow(x, 2, n)  # x = x**2 mod n
            next_k = True if x == n - 1 else False
            if x == 1 or x == n - 1:
                break
        if not next_k:
            return False

    return True


def random_prime(min, max, attempts=10000):
    """Generate a random prime in [min, max)"""
    # Try to get a prime <attepmts> times
    for _ in range(attempts):
        p = randrange(min, max)
        if is_prime(p):
            return p
    raise ValueError("Could not generate a prime number")


def random_bbs(bit_length=256, min_prime=2 ** 64, max_prime=2 ** 128):
    """Algorithm Blum-Blum-Shub.

    Generate a random number of bit_length bits.
    """
    # Get two large primes p,q = (3 mod 4)
    while True:
        p = random_prime(min_prime, max_prime)
        q = random_prime(min_prime, max_prime)
        if p % 4 == 3 and q % 4 == 3:
            break
    m = p * q

    # Get x which is relatively prime with m
    while True:
        x = random_prime(min_prime, max_prime)
        if gcd(m, x) == 1:
            break

    # Calculate x - generator starter
    num = 0
    x = pow(x, 2, m)    # x = x**2 mod m
    for k in range(bit_length):
        x = pow(x, 2, m)        # get next x
        num += (x & 1) << k     # add k-bit

    return num


def random_rfc6979(message: bytes, x: int, q: int,
                   curve_gen_point: ECPoint=None, sha_type="256"):
    """Algrorithm for generation determenistic random integers with RFC 6979.

    RFC 6979 - Deterministic Usage DSA and ECDSA.
    Parameters:
        message -- a sequence of bits,
        x -- private key for ECDSA,
        q -- the order of the elliptic curve,
        curve_gen_point -- generator point for the elliptic curve,
        sha_type -- type of hashing.
    """

    def bits2int(b: bytes):
        """Convert a sequence of bits to the non-negative integer.

        The result integer must be less than 2^qlen.
        If qlen < blen, then the qlen leftmost bits are kept
        (subsequent bits are discarded) and the result "right shift"
        by blen-qlen bits.
        Otherwise, qlen-blen bits (of value zero) are added to the
        left of the sequence.
        """
        blen = len(b) * 8
        num = int.from_bytes(b, byteorder="big", signed=False)
        result = num >> (blen - qlen) if qlen < blen else num
        return result

    def int2octets(i: int):
        """Convert an integer into a sequence of rlen bits"""
        result = i.to_bytes(rlen // 8, byteorder="big")
        return result

    def bits2octets(b: bytes):
        """Convert a sequence of bits to a sequence of rlen bits"""
        z1 = bits2int(b)
        z2 = z1 % q
        bits = int2octets(z2)
        result = (rlen // 8 - len(bits)) * b"\x00" + bits
        return result

    def test_suitable(k):
        """Check if k is suitable for ECDSA"""
        if curve_gen_point is None:
            return True
        else:
            C = curve_gen_point * k
            return C.x != 0

    # Preparation
    qlen = q.bit_length()
    rlen = 8 * ceil(qlen / 8)

    # step a
    h1 = sha(message, sha_type)
    hlen = len(h1)

    # step b
    v = b"\x01" * hlen

    # step c
    k = b"\x00" * hlen

    # step d
    k = hmac_sha(k, v + b"\x00" + int2octets(x) + bits2octets(h1), sha_type)

    # step e
    v = hmac_sha(k, v, sha_type)

    # step f
    k = hmac_sha(k, v + b"\x01" + int2octets(x) + bits2octets(h1), sha_type)

    # step g
    v = hmac_sha(k, v, sha_type)

    # step h
    while True:
        t = bytes()
        while len(t) * 8 < qlen:
            v = hmac_sha(k, v, sha_type)
            t += v

        kk = bits2int(t)
        # Check kk
        if 1 <= kk < q and test_suitable(kk):
            break
        else:
            k = hmac_sha(k, v + b"\x00", sha_type)
            v = hmac_sha(k, v, sha_type)

    return kk

