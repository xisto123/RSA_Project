# RSA_Project
Gerador/Verificador de Assinaturas
Implementação de um gerador e verificador de assinaturas RSA em arquivos.
Funcionalidades:
 - Geração de chaves (p e q primos com no mínimo de 1024 bits)
 - Cifração/decifração assimétrica RSA usando OAEP.

Assinatura
1. Cálculo de hashes da mensagem em claro (função de hash SHA-3)
2. Assinatura da mensagem (cifração do hash da mensagem)
3. Formatação do resultado (caracteres especiais e informações para verificação em
BASE64)

Verificação:
1. Parsing do documento assinado e decifração da mensagem (de acordo com a
formatação usada, no caso BASE64)
2. Decifração da assinatura (decifração do hash)
3. Verificação (cálculo e comparação do hash do arquivo)
