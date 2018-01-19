
# --- Usage and testing randoms.py ---
if __name__ == "__main__":

    from math import ceil
    from btc.utils import int2hex
    from btc.randoms import random_bbs, random_rfc6979

    # Generate a random integer in [1, 2^256) with Algorithm Blum-Blum-Shub
    print(int2hex(random_bbs(), None))


    # Generate the determenistic random for private key = x with RFC 6979
    # Check the results at https://tools.ietf.org/html/rfc6979#page-24

    # NIST P-256
    qlen = 256
    q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    print(int2hex(random_rfc6979(b"sample", x, q, None, "1"), ceil(qlen / 4)))

    # NIST B-409
    qlen = 409
    q = 0x10000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173
    x = 0x0494994CC325B08E7B4CE038BD9436F90B5E59A2C13C3140CD3AE07C04A01FC489F572CE0569A6DB7B8060393DE76330C624177
    print(int2hex(random_rfc6979(b"sample", x, q, None, "384"), ceil(qlen / 4)))

    # NIST K-163
    qlen = 163
    q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
    x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
    print(int2hex(random_rfc6979(b"test", x, q, None, "224"), ceil(qlen / 4)))

