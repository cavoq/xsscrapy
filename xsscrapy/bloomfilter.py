#       pybloomfilter.py
#       
#       Copyright 2009 ahmed youssef <xmonader@gmail.com>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.



__all__=["BloomFilter"]


from ctypes import *
import os

lib_path = os.path.abspath("libs/libcalg.so")
calg = CDLL(lib_path)
if not calg:
    print "Error loading libcalg.so"
    exit(1)

string_hash=calg.string_hash
string_hash.restype=c_ulong
string_hash.argstype=[c_void_p]

int_hash=calg.int_hash
int_hash.restype=c_ulong
int_hash.argstype=[c_void_p]

# bloomfilter c-definitions

bloomfilter_value=c_void_p
HASH_FUNC=CFUNCTYPE(c_ulong, bloomfilter_value)

class BloomFilterStruct(Structure):
    __fields__=[
        ("hash_func", HASH_FUNC),
        ("table", POINTER(c_ubyte)),
        ("table_size", c_uint ),
        ("num_functions",c_uint ),
    ]

bloomfilter_p = POINTER(BloomFilterStruct)

bf_new = calg.bloom_filter_new
bf_new.restype = bloomfilter_p
bf_new.argstype = [c_uint, HASH_FUNC, c_uint]

bf_free=calg.bloom_filter_free
bf_free.restype=None
bf_free.argstype=[bloomfilter_p]

bf_insert = calg.bloom_filter_insert
bf_insert.restype = None
bf_insert.argstype = [bloomfilter_p, bloomfilter_value]

bf_query = calg.bloom_filter_query
bf_query.restype = c_int
bf_query.argstype = [bloomfilter_p, bloomfilter_value]

# python wrapper

class BloomFilter:

    def __init__(self, table_size=128, hash_func=string_hash, num_functions=1):
        """
        A bloom filter is a space efficient data structure that can be used to test whether a given element is part of a set. 
        Lookups will occasionally generate false positives, but never false negatives.
        """
        self._bloomfilter = bf_new(table_size, hash_func, num_functions)

    def insert(self, val):
        """
        Insert a value into the bloom filter.
        """
        bf_insert(self._bloomfilter, str(val))

    def query(self, val):
        """
        Query a bloom filter for a particular value.
        """
        return bf_query(self._bloomfilter, str(val))

    def __contains__(self, val):
        """
        Check if a value is in the bloom filter.
        """
        return self.query(val)

    def __del__(self):
        """
        Explicitly free the resources allocated by the bloom filter.
        """
        if self._bloomfilter:
            bf_free(self._bloomfilter)


if __name__=="__main__":

    b=BloomFilter()
    b.insert("ahmed")
    b.insert("ayman")
    print "ahmed" in b
    print "ayman" in b
    print "memo" in b

    del b
