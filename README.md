# hc256
Python implementation of HC256 cipher.

**Not cryptographically secure.**

Sample usage:
```
import hc256

some_key = b"\x01\x02\x03\x04"
some_iv = b"\x01\x02\x03\x04"

data = bytes("Hello", "ascii")
ctx = hc256.HC256(some_key, some_iv)
cipher = ctx.crypt(data)
print(cipher)
```
