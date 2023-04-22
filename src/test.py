# Copyright (c) 2023 herrsmitty8128
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.
import hashlib

if __name__ == '__main__':

    with open('./src/lib.rs', 'r') as f:
        data = f.read().encode()

    h = hashlib.new('sha3_224')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha3_256')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha3_384')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha3_512')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha224')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha256')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha384')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha512')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha512-224')
    h.update(data)
    print(h.hexdigest())

    h = hashlib.new('sha512-256')
    h.update(data)
    print(h.hexdigest())
    
    h = hashlib.new('SHAKE128')
    h.update(data)
    print(h.hexdigest(length=44))
    
    h = hashlib.new('SHAKE256')
    h.update(data)
    print(h.hexdigest(length=44))
