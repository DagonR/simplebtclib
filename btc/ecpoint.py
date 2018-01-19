from btc.utils import mod_inverse, int2hex


# Parameters for SECP256k1 elliptic curve (used by Bitcoin)
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
SECP256K1_P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
SECP256K1_ORDER_LEN = SECP256K1_ORDER.bit_length()
SECP256K1_H = 1


class ECPoint:
    """Represents a point on an elliptic curve"""

    def __init__(self, x, y, a=SECP256K1_A, b=SECP256K1_B, mod=SECP256K1_P):
        """Construct an ECPoint on the elliptic curve:
                                       y^2 = x^3 + a*x + b (mod p)
        """
        # Check if the point(x,y) is the infinity
        if x or y:
            # Check if the point(x,y) is on the elliptic curve
            assert self.is_contained(x, y, a, b, mod), \
                   "The point {:x}, {:x} is not on " \
                   "the elliptic curve".format(x, y)
        self.x, self.y, self.a, self.b, self.mod = x, y, a, b, mod


    def __add__(self, other):
        if self.x == other.x and self.y == other.y:
            return self.double(self)
        else:
            return self.add(self, other)


    def __mul__(self, other):
        return self.multiply(self, other)


    def __repr__(self):
        return "({:s}, {:s})".format(int2hex(self.x), int2hex(self.y))


    def __eq__(self, other):
        return (self.x == other.x) & (self.y == other.y)


    def add(self, p1, p2):
        """Return the sum of two ECPoint"""
        # The sum of infinity + p2 = p2
        if p1 == ECPoint.infinity():
            return p2
        # The sum of p1 + infinity = p1
        if p2 == ECPoint.infinity():
            return p1

        # Check if the points are on a vertical line
        if p1.x == p2.x:
            # If p1 and p2 is the same then double(point)
            # else the result is infinity.
            if p1.y == p2.y:
                return self.double(p1)
            else:
                return ECPoint.infinity()

        # Sum point:
        #   x3 = s^2 - x1 - x2
        #   y3 = s(x1-x3) / y1
        # where s = (y2-y1) / (x2-x1)
        p3 = ECPoint(0, 0, p1.a, p1.b, p1.mod)
        dy = (p2.y - p1.y) % p1.mod
        dx = (p2.x - p1.x) % p1.mod
        s = (dy * mod_inverse(dx, p1.mod)) % p1.mod
        p3.x = (s * s - p1.x - p2.x) % p1.mod
        p3.y = (s * (p1.x - p3.x) - p1.y) % p1.mod

        return p3


    def double(self, p):
        """Return point * 2"""
        if p == ECPoint.infinity():
            return ECPoint.infinity()

        # Sum point:
        #   x3 = s^2 - x1 - x2
        #   y3 = s*(x1-x3) / y1
        # where s = (3*x^2 + a) / 2*y1
        p2 = ECPoint(0, 0, p.a, p.b, p.mod)
        dy = (3 * p.x * p.x + p.a) % p.mod
        dx = (2 * p.y) % p.mod

        s = (dy * mod_inverse(dx, p.mod)) % p.mod
        p2.x = (s * s - p.x - p.x) % p.mod
        p2.y = (s * (p.x - p2.x) - p.y) % p.mod

        return p2


    def multiply(self, p, x):
        """Return p * x = p + p + ... + p"""
        temp = ECPoint(p.x, p.y, p.a, p.b, p.mod)
        x = x - 1

        while x > 0:
            if x % 2 != 0:
                temp = self.double(temp) if temp == p else self.add(temp, p)
                x = x - 1
            x = x // 2
            p = self.double(p)

        return temp


    @staticmethod
    def infinity():
        """Return the infinity point on the elliptic curve point"""
        return ECPoint(0, 0)


    @staticmethod
    def is_contained(x, y, a, b, mod):
        """Check if a point is on the elliptic curve"""
        # The elliptic curve -- y^2 = x^3 + a*x + b (mod p)
        return (y ** 2 - (x ** 3 + a * x + b)) % mod == 0


    @classmethod
    def get_secp256k1_y(cls, x, a=SECP256K1_A, b=SECP256K1_B, p=SECP256K1_P):
        """Calculate y of a point with x"""
        # The elliptic curve -- y^2 = x^3 + a*x + b (mod p)
        # To solve y^2 = z mod p:
        #   if p mod 4 = 3  =>  y = z^((p+1)/4)
        # So for y^2 = x^3 + ax + b (mod p):
        #   y = (x^3 + ax + b)^((p+1)/4) (mod p)
        y = pow(x ** 3 + x * a + b, (p + 1) // 4, p)

        # Check if the point(x,y) is on the elliptic curve
        assert cls.is_contained(x, y, a, b, p), \
               "The point {:x}, {:x} is not on the elliptic curve".format(x, y)

        return y


    @staticmethod
    def get_secp256k1_a():
        return SECP256K1_A


    @staticmethod
    def get_secp256k1_b():
        return SECP256K1_B


    @staticmethod
    def get_secp256k1_gx():
        return SECP256K1_GX


    @staticmethod
    def get_secp256k1_gy():
        return SECP256K1_GY


    @staticmethod
    def get_secp256k1_p():
        return SECP256K1_P


    @staticmethod
    def get_secp256k1_order():
        return SECP256K1_ORDER


    @staticmethod
    def get_secp256k1_order_len():
        return SECP256K1_ORDER_LEN


    @staticmethod
    def get_secp256k1_h():
        return SECP256K1_H

