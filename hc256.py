import copy
from typing import List, Optional
import logging


def bit_check(n: bytes) -> int:
    return len(n) * 8


def rotr32(x: int, n: int) -> int:
    return (x >> n) + ((x << (32 - n))) & 0xffffffff


def rotl32(x: int, n: int) -> int:
    return (x << n) + ((x >> (32 - n))) & 0xffffffff


class HC256():
    def __init__(
        self,
        key: bytes,
        iv: bytes,
        log_level: Optional[int] = logging.WARN
    ):
        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

        if bit_check(key) != 256:
            self.logger.warning("keylen != 256 bits, null-padding")

        if bit_check(iv) != 256:
            self.logger.warning("ivlen != 256 bits, null-padding")

        key = key + b"\x00" * (32 - len(key))
        iv = iv + b"\x00" * (32 - len(iv))
        # Convert to list of DWORD
        self.key = [
            int.from_bytes(key[i:i+4], byteorder="little")
            for i in range(len(key))[::4]
        ]

        self.iv = [
            int.from_bytes(iv[i:i+4], byteorder="little")
            for i in range(len(iv))[::4]
        ]

        self.logger.debug(f"key: {self.key}")
        self.logger.debug(f"iv: {self.iv}")
        self.__init_cipher()
        self.ctr = 0

    def __init_cipher(self):
        def f1(x):
            return (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)) & 0xffffffff

        def f2(x):
            return (rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)) & 0xffffffff

        if len(self.key) != 8:
            raise ValueError("Invalid key len!")

        if len(self.iv) != 8:
            raise ValueError("Invalid IV len!")

        self.logger.debug("Setting key/IV")
        self.ctr = 0
        w = [0] * 2560
        self.P = None
        self.Q = None

        for i in range(len(self.key)):
            w[i] = self.key[i]
            w[i+8] = self.iv[i]

        for i in range(16, 2560):
            w[i] = ((
                ((f2(w[i-2]) + w[i-7]) & 0xffffffff) +
                (f1(w[i-15]) + w[i-16]) & 0xffffffffff
            ) + i) & 0xffffffff
        self.P = w[512:1536]
        self.Q = w[1536:]
        if len(self.P) != 1024 or len(self.Q) != 1024:
            raise ValueError(f"P/Q invalid len: P: {len(self.P)}, Q: {len(self.Q)}")
        # Run 4096 iters.
        self.logger.debug("Running keystream iterations before cipher")
        for i in range(4096):
            self.keystream()

    def keystream(self) -> int:
        r = None

        def g1(x: int, y: int) -> int:
            return ((rotr32(x, 10) ^ rotr32(y, 23)) + self.Q[(x ^ y) % 1024]) & 0xffffffff

        def g2(x: int, y: int) -> int:
            return ((rotr32(x, 10) ^ rotr32(y, 23)) + self.P[(x ^ y) % 1024]) & 0xffffffff

        def h1(x: int) -> int:
            r = self.Q[x & 0xff]
            r = (r + self.Q[256 + ((x >> 8) & 0xff)]) & 0xffffffff
            r = (r + self.Q[512 + ((x >> 16) & 0xff)]) & 0xffffffff
            r = (r + self.Q[768 + ((x >> 24) & 0xff)]) & 0xffffffff
            return r & 0xffffffff

        def h2(x: int) -> int:
            r = self.P[x & 0xff]
            r = (r + self.P[256 + ((x >> 8) & 0xff)]) & 0xffffffff
            r = (r + self.P[512 + ((x >> 16) & 0xff)]) & 0xffffffff
            r = (r + self.P[768 + ((x >> 24) & 0xff)]) & 0xffffffff
            return r & 0xffffffff

        j = self.ctr & 0x3ff
        j3 = (j - 3) % 1024
        j10 = (j - 10) % 1024
        j12 = (j - 12) % 1024
        j1023 = (j - 1023) % 1024
        if self.ctr < 1024:
            self.P[j] = (
                self.P[j] +
                self.P[j10] +
                g1(self.P[j3], self.P[j1023])
            ) & 0xffffffff
            r = h1(self.P[j12])
            r = (r ^ self.P[j]) & 0xffffffff
        else:
            self.Q[j] = (
                self.Q[j] +
                self.Q[j10] +
                g2(self.Q[j3], self.Q[j1023])
            ) & 0xffffffff
            r = h2(self.Q[j12])
            r = (r ^ self.Q[j]) & 0xffffffff

        self.ctr = (self.ctr + 1) & 0x7ff
        return r

    def crypt(self, cipher: bytes) -> bytes:
        uncipher = list(cipher)
        i = 0
        while i < len(cipher):
            k = self.keystream()
            self.logger.debug(f"keystream[{i}]: {k}")
            j = 0
            while (j < 4 and i < len(cipher)):
                uncipher[i] ^= (k & 0xff)
                i += 1
                j += 1
                k = (k >> 8)

        return bytes(uncipher)


def main():
    test_hc256()


def test_hc256():
    test_cases = [
        {
            "key": b"\x00",
            "iv": b"\x00",
            "expect": [
                0x5b, 0x07, 0x89, 0x85, 0xd8, 0xf6, 0xf3, 0x0d,
                0x42, 0xc5, 0xc0, 0x2f, 0xa6, 0xb6, 0x79, 0x51,
                0x53, 0xf0, 0x65, 0x34, 0x80, 0x1f, 0x89, 0xf2,
                0x4e, 0x74, 0x24, 0x8b, 0x72, 0x0b, 0x48, 0x18
            ]
        },
        {
            "key": b"\x00",
            "iv": b"\x01",
            "expect": [
                0xaf, 0xe2, 0xa2, 0xbf, 0x4f, 0x17, 0xce, 0xe9,
                0xfe, 0xc2, 0x05, 0x8b, 0xd1, 0xb1, 0x8b, 0xb1,
                0x5f, 0xc0, 0x42, 0xee, 0x71, 0x2b, 0x31, 0x01,
                0xdd, 0x50, 0x1f, 0xc6, 0x0b, 0x08, 0x2a, 0x50
            ]
        },
        {
            "key": b"\x55",
            "iv": b"\x00",
            "expect": [
                0x1c, 0x40, 0x4a, 0xfe, 0x4f, 0xe2, 0x5f, 0xed,
                0x95, 0x8f, 0x9a, 0xd1, 0xae, 0x36, 0xc0, 0x6f,
                0x88, 0xa6, 0x5a, 0x3c, 0xc0, 0xab, 0xe2, 0x23,
                0xae, 0xb3, 0x90, 0x2f, 0x42, 0x0e, 0xd3, 0xa8
            ]
        }
    ]
    i = 0
    for test in test_cases:
        ctx = HC256(test["key"], test["iv"], logging.DEBUG)
        test_data = b"\0"*32
        output = ctx.crypt(test_data)
        if output != bytes(test["expect"]):
            raise ValueError(
                f"Test {i} failed!\nGot: {output}\nExpected: {bytes(test['expect'])}"
            )
        i += 1
    print("Tests passed")


if __name__ == '__main__':
    main()
