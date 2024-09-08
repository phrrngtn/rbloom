import mmh3
from rbloom import Bloom

from functools import partial
from pyxll import xl_func

class BloomWrapper(object):
    def __init__(self, expected_items, false_positive_rate, hash_func=None):
        self.bloom = Bloom(
            expected_items=expected_items,
            false_positive_rate=false_positive_rate,
            hash_func=hash_func,
        )
        self.expected_items = expected_items
        self.false_positive_rate = false_positive_rate
        self.hash_func = hash_func

    def __contains__(self, obj):
        return obj in self.bloom

    def __getattr__(self, name):
        return getattr(self.bloom, name)

    def intersection(self, other):
        wrapper = BloomWrapper(
            expected_items=self.expected_items,
            false_positive_rate=self.false_positive_rate,
            hash_func=self.hash_func,
        )
        wrapper.bloom = self.bloom.intersection(other.bloom)
        return wrapper

    def union(self, other):
        wrapper = BloomWrapper(
            expected_items=self.expected_items,
            false_positive_rate=self.false_positive_rate,
            hash_func=self.hash_func,
        )

        wrapper.bloom = self.bloom.union(other.bloom)
        return wrapper

    def issuperset(self, other):
        return self.bloom.issuperset(other.bloom)

    def issubset(self, other):
        return self.bloom.issubset(other.bloom)

BLOOM_DEFAULT_EXPECTED_ITEMS = 100_000
BLOOM_DEFAULT_FALSE_POSITIVE_RATE = 0.001

mmh3_signed_128bit = partial(mmh3.hash128, signed=True)


@xl_func(
    "str[] symbols, int expected_items, float false_positive_rate: object",
    name="BF.BF",
    recalc_on_open=True,
)
def bloom_filter(symbols, expected_items=100_000, false_positive_rate=0.001):
    bf = BloomWrapper(
        expected_items=expected_items,
        false_positive_rate=false_positive_rate,
        hash_func=mmh3_signed_128bit,
    )
    bf.expected_items = expected_items
    bf.false_positive_rate = false_positive_rate
    bf.update(symbols)
    return bf

@xl_func("object,object: object", name="BF.INTERSECTION")
def bloom_filter_intersection(bloom, other):
    return bloom.intersection(other)


@xl_func("object,object: object", name="BF.UNION")
def bloom_filter_intersection(bloom, other):
    return bloom.union(other)


@xl_func("object,object: bool", name="BF.IS_SUBSET")
def bloom_filter_issubset(bloom, other):
    return bloom.issubset(other)


@xl_func("object,object: bool", name="BF.IS_SUPERSET")
def bloom_filter_issuperset(bloom, other):
    return bloom.issuperset(other)
