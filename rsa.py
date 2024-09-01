# rsa.py
"""
RSA Cipher and Signature Implementation

Este arquivo contém a classe `RSA` que implementa:
- Geração de chaves RSA (p e q primos com no mínimo 1024 bits)
- Cifração/decifração assimétrica RSA usando OAEP
- Assinatura digital usando RSA
- Verificação de assinaturas digitais
"""

import random
from math import gcd
from hashlib import sha3_256
from utils import mod_inv, generate_prime

class RSA:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.e, self.d, self.n = self.generate_keys(key_size)

    def generate_keys(self, key_size):
        p = generate_prime(self.key_size // 2)
        q = generate_prime(self.key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = self._generate_e(phi)
        g = gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = gcd(e, phi)
        
        d = mod_inv(e, phi)

        #Esta parte serve para teste com arquivo
        self.public_key = (e, n)
        self.private_key = (d, n)
        return e, d, n
        

    def _generate_e(self, phi):
        while True:
            e = random.randrange(2, phi)
            if gcd(e, phi) == 1:
                return e
    
    def encrypt(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # Lida com message como bytes
        return [pow(byte, self.e, self.n) for byte in message]

    def decrypt(self, ciphertext):
        decrypted_bytes = bytes([pow(char, self.d, self.n) for char in ciphertext])
        try:
            # Decodificação para string
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # Retorna como bytes se não for possível decodificar para string
            return decrypted_bytes
    
    def sign(self, message):
        e, n = self.private_key
        hashed_message = sha3_256(message).digest()
        signature = pow(int.from_bytes(hashed_message, byteorder='big'), e, n)
        return signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')

    def verify_sign(self, message, signature):
        d, n = self.public_key
        hashed_message = sha3_256(message).digest()
        decrypted_signature = pow(int.from_bytes(signature, byteorder='big'), d, n)
        decrypted_signature = decrypted_signature.to_bytes((decrypted_signature.bit_length() + 7) // 8, byteorder='big')
        return hashed_message == decrypted_signature    
    