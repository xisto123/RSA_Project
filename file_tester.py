# file_tester.py
"""
File Signature Testing

Este arquivo contém a lógica para testar a geração e verificação de assinaturas RSA em arquivos:
- Gera as chaves RSA
- Cria uma assinatura digital para um arquivo
- Verifica a assinatura de um arquivo assinado
"""

import base64
from rsa import RSA

def generate_keys_and_sign_file(filename):
    rsa = RSA(key_size=2048)
    rsa.generate_keys(rsa.key_size)

    with open(filename, 'rb') as f:
        data = f.read()

    signature = rsa.sign(data)
    
    with open(filename + '.sig', 'wb') as f:
        f.write(base64.b64encode(signature))
    
    return rsa, signature

def verify_file_signature(filename, rsa):
    with open(filename, 'rb') as f:
        data = f.read()

    with open(filename + '.sig', 'rb') as f:
        signature = base64.b64decode(f.read())

    if rsa.verify_sign(data, signature):
        print("Assinatura válida.")
    else:
        print("Assinatura inválida.")
