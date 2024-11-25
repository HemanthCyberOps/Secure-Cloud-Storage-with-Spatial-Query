import hashlib
import numpy as np


def serialize(element):
    """Serialize complex objects into a consistent string format."""
    if isinstance(element, dict):
        return str(sorted(element.items()))  # Ensure consistent ordering
    return str(element)


class MultiLevelBloomFilter:
    def __init__(self, levels=3, dimensions=(20, 20, 20), num_hashes=14):
        self.levels = levels
        self.filters = [
            BloomFilter(dimensions, num_hashes) for _ in range(levels)
        ]

def add(self, field, value):
    if not field or not value:
        raise ValueError("Field and value must be non-empty.")
    serialized_element = serialize(f"{field}:{value}")
    for hash_func in self.hash_funcs:
        x, y, z = [hash_func(serialized_element) % dim for dim in self.dimensions]
        self.bit_array[x, y, z] = True

def lookup(self, field, value):
    if not field or not value:
        return False
    serialized_element = serialize(f"{field}:{value}")
    for hash_func in self.hash_funcs:
        x, y, z = [hash_func(serialized_element) % dim for dim in self.dimensions]
        if not self.bit_array[x, y, z]:
            return False
    return True


class BloomFilter:
    def __init__(self, dimensions=(20, 20, 20), num_hashes=14):
        self.dimensions = dimensions
        self.num_hashes = num_hashes
        self.bit_array = np.zeros(dimensions, dtype=bool)
        self.hash_funcs = [
            lambda x, seed=i: int(hashlib.sha224(f"{seed}{x}".encode()).hexdigest(), 16)
            for i in range(num_hashes)
        ]

    def add(self, field, value):
        serialized_element = serialize(f"{field}:{value}")
        for hash_func in self.hash_funcs:
            x, y, z = [hash_func(serialized_element) % dim for dim in self.dimensions]
            self.bit_array[x, y, z] = True

    def lookup(self, field, value):
        serialized_element = serialize(f"{field}:{value}")
        for hash_func in self.hash_funcs:
            x, y, z = [hash_func(serialized_element) % dim for dim in self.dimensions]
            if not self.bit_array[x, y, z]:
                return False
        return True
