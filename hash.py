# hash.py
"""
Hash Function Implementation

Este arquivo contém a função de hash usada para a assinatura digital:
- sha3_256: Função de hash baseada no SHA-3 256 bits
"""

from hashlib import sha3_256

def hash_function(data):
    return sha3_256(data).digest()
