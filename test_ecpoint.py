
# --- Usage and testing ---
if __name__ == "__main__":

    from btc.ecpoint import ECPoint

    # Find the nearest point with x coordinate >= start_x
    start_x = 10 ** 33

    while True:
        try:
            p = ECPoint(start_x, ECPoint.get_secp256k1_y(start_x))
            break
        except AssertionError:
            start_x += 1
            continue

    print(p)
