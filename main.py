# main.py
"""
Main Script for Testing RSA Encryption and Decryption

Este arquivo contém o código para testar:
- Geração de chaves RSA com teste de primalidade (Miller-Rabin).
- Cifração e decifração RSA simples.
- Cifração e decifração RSA usando OAEP.
- Assinatura e verificação de um arquivo
"""

from rsa import RSA
from oaep import oaep_pad, oaep_unpad
from file_tester import generate_keys_and_sign_file, verify_file_signature

def test_key_generation():
    rsa = RSA(key_size=2048)
    
    print("\n === Testando geração de chaves RSA ===")
    print("Chaves RSA geradas:")
    print(f"\n Chave Publica: {rsa.public_key}")
    print(f"\n Chave Privada: {rsa.private_key}")

def test_rsa_cipher():
    rsa = RSA(key_size=2048)
    
    print("\n === Testando cifração e decifração RSA ===")
    
    message = "Esta é uma mensagem secreta."
    print(f"Mensagem Original: {message}")
    
    ciphertext = rsa.encrypt(message)
    print(f"Mensagem criptografada: {ciphertext}")

    decrypted_message = rsa.decrypt(ciphertext)
    print(f"Mensagem decifrada: {decrypted_message}")

    if message == decrypted_message:
        print("Sucesso! A decifragem corresponde ao texto original.")
    else:
        print("Erro! A decifragem não corresponde ao texto original.")

def test_rsa_cipher_oaep():
    rsa = RSA(key_size=2048)
    
    print("\n === Testando cifração e decifração RSA com OAEP ===")
    message = "Esta é uma mensagem secreta."

    # Aplicando padding OAEP e Cifra
    padded_message = oaep_pad(message.encode(), rsa.key_size)
    ciphertext_oaep = rsa.encrypt(padded_message)
    print(f"Mensagem criptografada (com OAEP): {ciphertext_oaep}")

    # Removendo padding OAEP e Decifração
    unpadded_message = oaep_unpad(rsa.decrypt(ciphertext_oaep), rsa.key_size)
    decrypted_message = unpadded_message.decode()
    print(f"Mensagem decifrada (com OAEP): {decrypted_message}")

    if message == decrypted_message:
        print("Sucesso! A decifragem corresponde ao texto original.")
    else:
        print("Erro! A decifragem não corresponde ao texto original.")

def test_file_signature():
    print("\n=== Teste de Assinatura e Verificação de Arquivo ===")
    
    # Nome do arquivo a ser assinado
    file_to_sign = "arquivo.txt"
    
    # Geração de chaves e assinatura do arquivo
    rsa, signature = generate_keys_and_sign_file(file_to_sign)
    print(f"Assinatura gerada: {signature}")
    
    # Verificação da assinatura do arquivo
    verify_file_signature(file_to_sign, rsa)

if __name__ == "__main__":    
    # Testa a Geração de chaves RSA com teste de primalidade (Miller-Rabin).
    test_key_generation()
    
    # Testa a Cifração e decifração RSA simples.
    test_rsa_cipher()
    
    # Testa a Cifração e decifração RSA usando OAEP.
    test_rsa_cipher_oaep()
    
    # Testa a assinatura e verificação de um arquivo
    test_file_signature()
