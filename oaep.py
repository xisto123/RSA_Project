# oaep.py
"""
OAEP Padding Implementation

Este arquivo contém as funções para adicionar e remover padding OAEP usado na cifra RSA:
- oaep_pad: Adiciona padding OAEP aos dados
- oaep_unpad: Remove padding OAEP dos dados decifrados
"""

import hashlib
import os
from utils import xor_bytes, mgf1

def oaep_pad(message, key_size, hash_algo=hashlib.sha3_256):
    k = key_size // 8
    h_len = hash_algo().digest_size
    ps_len = k - len(message) - 2 * h_len - 2
    if ps_len < 0:
        raise ValueError("O tamanho da mensagem é muito grande.")
    
    ps = b'\x00' * ps_len
    padded_message = b'\x00' + ps + b'\x01' + message
    
    seed = os.urandom(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_algo)
    masked_db = xor_bytes(padded_message, db_mask)
    seed_mask = mgf1(masked_db, h_len, hash_algo)
    masked_seed = xor_bytes(seed, seed_mask)
    
    return b'\x00' + masked_seed + masked_db

def oaep_unpad(padded_message, key_size, hash_algo=hashlib.sha3_256):
    k = key_size // 8
    h_len = hash_algo().digest_size
    
    #Validacao comentada por motivos desconhecidos, rever depois!
    #if len(padded_message) != k or padded_message[0] != 0:
        #raise ValueError("Erro na remoção do padding: dados inválidos.")
    
    masked_seed = padded_message[1:h_len + 1]
    masked_db = padded_message[h_len + 1:]
    
    seed_mask = mgf1(masked_db, h_len, hash_algo)
    seed = xor_bytes(masked_seed, seed_mask)
    
    db_mask = mgf1(seed, k - h_len - 1, hash_algo)
    db = xor_bytes(masked_db, db_mask)
    
    separator_index = db.find(b'\x01', h_len)
    
    if separator_index == -1:
        raise ValueError("Erro na remoção do padding: separador não encontrado.")
    
    return db[separator_index + 1:]
