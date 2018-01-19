from hashlib import pbkdf2_hmac

from btc.utils import sha256, bytes2int, int2bytes


class BIP39:
    """Represents BIP39 mnemonic code"""

    def __init__(self, wordlist_file: str):
        """Construct a BIP39 and load 2048 words in a dict"""
        with open(wordlist_file, 'r') as f:
            self._wordlist = [word.strip() for word in f]


    def entropy_to_mnemonic(self, entropy: bytes):
        """Calculate a mnemonic phrase from an entropy.

        Parameters:
            entropy -- a random bytes in a multiple of 32 bits
                       (length - 128-256 bits).
        Return a list with mnemonic words.
        """
        ent_len = 8 * len(entropy)
        # Check a multiple of 32 bits
        if ent_len < 32 or ent_len % 32 != 0:
            raise Exception("Invalid entropy length")

        # cs_len -- length of checksum
        cs_len = ent_len // 32
        checksum = bytes2int(sha256(entropy)[0:2]) >> (16 - cs_len)

        ent_cs = (bytes2int(entropy) << cs_len) | checksum

        words_count = (ent_len + ent_len // 32) // 11

        mnemonic = [
            self._wordlist[(ent_cs >> 11*x) & 0x7FF].strip()
                for x in range(words_count)
        ]
        # Reverse the list
        return mnemonic[::-1]


    def mnemonic_to_entropy(self, mnemonic: list):
        """Calculate an entropy from a mnemonic phrase.

        Parameters:
            mnemonic -- a list with mnemonic words in a multiple of
            3 words (length - 12-24 words).
        Return bytes in a multiple of 32 bits (length - 128-256 bits).
        """
        words_count = len(mnemonic)

        # Check number of words
        if words_count < 12 or words_count > 24 or words_count % 3 !=0:
            raise Exception("Invalid number of the words")

        ent_len = words_count * 11 * 32 // 33
        ent_cs = 0

        for x in mnemonic:
            try:
                ent_cs = (ent_cs << 11) | self._wordlist.index(x)
            except ValueError:
                raise ValueError("Invalid word: '{:s}'".format(x))

        return int2bytes(ent_cs >> (ent_len // 32), ent_len // 8)


    @staticmethod
    def mnemonic_to_seed(mnemonic: list, password: str):
        """Calculate a seed from a mnamonic phrase and a secret phrase

        Parameters:
            mnemonic -- a list with mnemonic words in a multiple of
            3 words (length - 12-24 words),
            password -- a secret phrase.
        Return -- a seed of 64 bytes.
        """
        return pbkdf2_hmac(
            "sha512", " ".join(mnemonic).encode(),
            b"mnemonic" + password.encode(),
            2048
        )
