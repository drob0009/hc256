import hc256
import logging


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
        ctx = hc256.HC256(test["key"], test["iv"], logging.DEBUG)
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
