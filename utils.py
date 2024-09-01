# utils.py
"""
Utility Functions

Este arquivo contém funções utilitárias para outras partes do código:
- Função para calcular o inverso modular
- Função para gerar números primos
- Função para verificar se eh primo
- Função para realizar XOR entre bytes
- Função MGF1 (Mask Generation Function) usada no padding OAEP
"""

import random
import hashlib

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def mgf1(seed, mask_len, hash_algo=hashlib.sha3_256):
    hash_len = hash_algo().digest_size
    if mask_len > 2**32 * hash_len:
        raise ValueError("mask_len too large")
    T = b""
    for i in range((mask_len + hash_len - 1) // hash_len):
        C = i.to_bytes(4, byteorder="big")
        T += hash_algo(seed + C).digest()
    return T[:mask_len]

def mod_inv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
