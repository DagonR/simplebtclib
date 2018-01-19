import struct

from btc.utils import sha256, signature_to_der, int2bytes
from btc.keys import KeysBTC


OP_DUP = b"\x76"
OP_EQUAL = b"\x87"
OP_EQUALVERIFY = b"\x88"
OP_HASH160 = b"\xa9"
OP_CHECKSIG = b"\xac"
OP_CHECKMULTISIG = b"\xae"

class TransactBTC:
    """Represents forming and signing Bitcoin transactions"""

    def __init__(self, b: KeysBTC):
        """Construct an object"""
        # Init a dictionary with transaction inputs
        self.ins = {}
        # Init a dictionary with transaction outputs
        self.outs = {}


    def __repr__(self):
        cur_tx = self.gen_transaction(to_sign=False)
        return \
            str({
                "tx_hash": sha256(sha256(cur_tx))[::-1].hex(),
                "tx": cur_tx.hex()
            })


    @staticmethod
    def get_script_sig(r: bytes, s: bytes, public_key: bytes):
        """Construct an unlocking script with a sign [r, s]"""
        # Convert r and s to DER
        sig = signature_to_der(r, s)
        # Construct a sigScript = DER(DER(r,s)+01) + <length pubkey> + <pubkey>
        return (
            int2bytes(len(sig) + 1, 1) +
            sig +
            b"\x01" +
            int2bytes(len(public_key), 1) +
            public_key
        )


    @staticmethod
    def get_script_p2pkh(hash: bytes):
        """Construct a locking pay-to-pubkey-hash script (p2pkh):

        OP_DUP OP_HASH160 <len of pubkey hash> <pubkey hash> OP_CHECKSIG
        """
        return (
            OP_DUP +
            OP_HASH160 +
            int2bytes(len(hash), 1) +
            hash +
            OP_EQUALVERIFY +
            OP_CHECKSIG
        )


    @staticmethod
    def get_script_p2sh(hash):
        """Construct a locking pay-to-script-hash script (p2sh):

        OP_HASH160 <len of script hash> <script hash> OP_EQUAL
        """
        return (
            OP_HASH160 +
            int2bytes(len(hash), 1) +
            hash +
            OP_EQUAL
        )


    def add_in_transaction(self, tx_hash, index: int, keys: KeysBTC):
        """Add an input to the transaction"""

        # Convert tx_hash to bytes if it's str
        tx_hash = bytes.fromhex(tx_hash) \
            if isinstance(tx_hash, str) else tx_hash

        # Init a dictionary for an input
        tx_in = {}

        # Previous transaction hash -- tx_hash
        tx_in["previous_tx_hash"] = tx_hash[::-1]

        # Output point index -- index
        tx_in["previous_txout_index"] = struct.pack("<L", index)

        # Temporary signature script = output script
        # Generate a script with BTC-address for -- keys
        tx_in["script_sig"] = self.get_script_p2pkh(keys.get_pubkey_hash())

        # Temporary signature script length
        tx_in["script_length"] = struct.pack("<B", len(tx_in["script_sig"]))

        # Sequence 0xFFFFFFFF
        tx_in["sequence"] = b"\xff\xff\xff\xff"

        # Set a KeysBTC object using to sign this input
        tx_in["keys"] = keys

        # Add the dictionary with the input to the transaction
        self.ins[len(self.ins)] = tx_in
        return


    def add_out_transaction(self, to_hash, value: int, tx_type: str="p2pkh"):
        """Add an output to the transaction"""

        # Convert to_hash to public key hash if it's str
        to_hash = KeysBTC.address_to_pubkey_hash(to_hash) \
            if isinstance(to_hash, str) else to_hash

        # Init a dictionary for an output
        tx_out = {}

        # Amount in satoshies (8 bytes) -- value
        tx_out["value"] = struct.pack("<Q", value)

        # Output script (depends on type: p2pkh or p2sh)
        if tx_type == "p2pkh":
            tx_out["script_pubkey"] = self.get_script_p2pkh(to_hash)
        elif tx_type == "p2sh":
            tx_out["script_pubkey"] = self.get_script_p2sh(to_hash)
        else:
            raise ValueError("Invalid transaction type: {:s}".format(tx_type))

        # Output script length
        tx_out["script_length"] = \
            struct.pack("<B", len(tx_out["script_pubkey"]))

        # Add the dictionary with the output to the transaction
        self.outs[len(self.outs)] = tx_out
        return


    def gen_transaction(self, input_num=0, to_sign=True):
        """Prepare a transaction.

        If to sign is True - it's a temporary transaction for
        signing the input (with input_num), else it's a final
        transaction and input_num is ignored.
        """

        # Set version (0x00000001)
        version = struct.pack("<L", 1)
        tx_to_sign = version

        # Construct the inputs
        # Number of the inputs
        tx_in_count = struct.pack("<B", len(self.ins))
        tx_to_sign += tx_in_count

        # Inputs:
        for i in self.ins.keys():
            # If it's a transaction to sign then set temporary scripts
            if to_sign:
                # Scripts for all inputs beside the signing is
                # empty (length=0, sig=[])
                script_length = b"\x00" \
                    if i != input_num else self.ins[i]["script_length"]
                script_sig = bytes() \
                    if i != input_num else self.ins[i]["script_sig"]
            # Otherwise, set final signature scripts
            else:
                script_length = self.ins[i]["final_script_length"]
                script_sig = self.ins[i]["final_script_sig"]

            # Add the input
            tx_to_sign += self.ins[i]["previous_tx_hash"] + \
                          self.ins[i]["previous_txout_index"] + \
                          script_length + \
                          script_sig + \
                          self.ins[i]["sequence"]

        # Construct the outputs
        # Number of the outputs
        tx_out_count = struct.pack("<B", len(self.outs))
        tx_to_sign += tx_out_count
        # Outputs:
        for i in self.outs.keys():
            # Add the output
            tx_to_sign += self.outs[i]["value"] + \
                          self.outs[i]["script_length"] + \
                          self.outs[i]["script_pubkey"]

        # Set a lock time
        lock_time = struct.pack("<L", 0)
        tx_to_sign += lock_time

        # If it's a transaction to sign then add flag SIGHASH_ALL
        hash_code_type = struct.pack("<L", 1)
        tx_to_sign += hash_code_type if to_sign else bytes()

        return tx_to_sign


    def sign_all_inputs(self):
        """Sign this transaction"""
        # For each input prepare and sign a transaction
        for i in self.ins.keys():

            # Prepare the transaction to sign for the input = i
            temp_tx = self.gen_transaction(input_num=i, to_sign=True)

            # Get the hash
            hash_temp_tx = sha256(sha256(temp_tx))

            # Sign the prepared transaction
            r, s = self.ins[i]["keys"].sign(hash_temp_tx)

            # Save the final script signature and it's length
            self.ins[i]["final_script_sig"] = \
                self.get_script_sig(r, s, self.ins[i]["keys"].get_public_key())

            self.ins[i]["final_script_length"] = \
                struct.pack("<B", len(self.ins[i]["final_script_sig"]))
        return

