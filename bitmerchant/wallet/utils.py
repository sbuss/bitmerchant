from functools import wraps
import re

import hashlib
from hashlib import sha256


def hash160(data):
    """Return ripemd160(sha256(data))"""
    rh = hashlib.new('ripemd160', sha256(data).digest())
    return rh.digest()


def is_hex_string(string):
    """Check if the string is only composed of hex characters."""
    return re.match(r'[A-Fa-f0-9]+', string) is not None


def long_to_hex(l, size):
    """Encode a long value as a hex string, 0-padding to size.

    Note that size is the size of the resulting hex string. So, for a 32Byte
    long size should be 64 (two hex characters per byte"."""
    f_str = "{0:0%sx}" % size
    return f_str.format(l).lower()


def memoize(f):
    """Memoization decorator for a function taking one or more arguments."""
    def _c(*args, **kwargs):
        if not hasattr(f, 'cache'):
            f.cache = dict()
        key = (args, tuple(kwargs))
        if key not in f.cache:
            f.cache[key] = f(*args, **kwargs)
        return f.cache[key]
    return wraps(f)(_c)
