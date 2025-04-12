# Constantes K (primeiros 32 bits das partes fracionárias das raízes cúbicas dos 64 primeiros primos)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Valores iniciais do hash (primeiros 32 bits das partes fracionárias das raízes quadradas dos 8 primeiros primos)
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def right_rotate(x, n):
    """Rotação circular à direita de n bits"""
    return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

def sigma0(x):
    """Função σ0 do SHA-256"""
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)

def sigma1(x):
    """Função σ1 do SHA-256"""
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)

def Sigma0(x):
    """Função Σ0 do SHA-256"""
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)

def Sigma1(x):
    """Função Σ1 do SHA-256"""
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)

def Ch(x, y, z):
    """Função de escolha (Choice)"""
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    """Função de maioria (Majority)"""
    return (x & y) ^ (x & z) ^ (y & z)

def preprocess_message(message):
    """Prepara a mensagem conforme o padrão SHA-256"""
    # Converter a mensagem para bytes se for string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Comprimento original em bits
    original_length = len(message) * 8
    
    # Adicionar padding: 1 bit '1' seguido de zeros
    message += b'\x80'  # 10000000 em binário
    
    # Adicionar zeros até que o comprimento ≡ 448 mod 512
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    # Adicionar comprimento original como inteiro de 64 bits big-endian
    message += original_length.to_bytes(8, byteorder='big')
    
    return message

def process_block(block, H):
    """Processa um bloco de 512 bits"""
    # Dividir o bloco em 16 palavras de 32 bits (big-endian)
    W = []
    for i in range(0, 64, 4):
        W.append(int.from_bytes(block[i:i+4], byteorder='big'))
    
    # Estender para 64 palavras
    for t in range(16, 64):
        W.append((sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]) & 0xFFFFFFFF)
    
    # Inicializar variáveis de trabalho
    a, b, c, d, e, f, g, h = H
    
    # Loop principal de 64 rounds
    for t in range(64):
        T1 = (h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
        T2 = (Sigma0(a) + Maj(a, b, c)) & 0xFFFFFFFF
        
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF
    
    # Atualizar o hash
    new_H = [
        (H[0] + a) & 0xFFFFFFFF,
        (H[1] + b) & 0xFFFFFFFF,
        (H[2] + c) & 0xFFFFFFFF,
        (H[3] + d) & 0xFFFFFFFF,
        (H[4] + e) & 0xFFFFFFFF,
        (H[5] + f) & 0xFFFFFFFF,
        (H[6] + g) & 0xFFFFFFFF,
        (H[7] + h) & 0xFFFFFFFF
    ]
    
    return new_H

def sha256(message):
    """Calcula o hash SHA-256 de uma mensagem"""
    # Pré-processamento
    message = preprocess_message(message)
    
    # Inicializar valores do hash
    H = H_INIT.copy()
    
    # Processar cada bloco de 512 bits (64 bytes)
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        H = process_block(block, H)
    
    # Produzir o hash final concatenando os valores H
    hash_bytes = b''.join([h.to_bytes(4, byteorder='big') for h in H])
    hash_hex = ''.join([f'{b:02x}' for b in hash_bytes])
    
    return hash_hex

# Teste com strings conhecidas
test_cases = [
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),   # Certo
    ("olá", "d3d10a1e1f26c73110a573f4a6b2cc244e8b4a1a3a9e60a9d82790c7e8d6c6f"), # Errado
    ("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592") # Certo
]

for message, expected in test_cases:
    result = sha256(message)
    print(f"Mensagem: '{message}'")
    print(f"Esperado: {expected}")
    print(f"Resultado: {result}")
    print(f"Correto? {result == expected}\n")