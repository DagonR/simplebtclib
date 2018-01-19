
if __name__ == "__main__":

    from btc.keys import KeysBTC
    from btc.transact import TransactBTC

    # Prepare transaction
    keys_from = KeysBTC(
        "5842f1ee4fe0517a09acf03a21798bd88b30611e34a3a6092ac2ae4c27c2ae27"
    )
    keys_from.get_address(version=keys_from.get_addr_ver_test())    # testnet
    print(keys_from)


    # Prepare a transaction
    tx = TransactBTC(keys_from)

    tx.add_in_transaction(
        # previous ttransaction hash
        "fd17a13054a3c1647120d5280f416878d5f375ccc864d29e7902cfd8fbde6284",
        1,  # output
        keys_from   # KeysBTC object for signing
    ) # for example, the output is 0.50000000 btc

    tx.add_out_transaction(
        "2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF",
        49950000,   # value
        tx_type="p2sh"  # pay-to-script-hash
    )

    tx.sign_all_inputs()

    print(tx)
