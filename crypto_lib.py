
import hashlib
import os
import base64
import math

# --- Funções Aritméticas e de Primalidade ---

def is_prime(n, k=40):
    """
    Teste de primalidade de Miller-Rabin.
    k é o número de rodadas de teste para garantir a acurácia.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = os.urandom(16) # Pega um número aleatório
        a = int.from_bytes(a, 'big') % (n - 3) + 2 # Garante a no intervalo [2, n-2]

        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Gera um número primo com a quantidade de bits especificada."""
    while True:
        # Gera um número ímpar aleatório com o número correto de bits
        p = int.from_bytes(os.urandom(bits // 8), 'big')
        p |= (1 << (bits - 1)) | 1 # Garante que tenha 'bits' e seja ímpar
        
        if is_prime(p):
            return p

def extended_gcd(a, b):
    """Algoritmo Estendido de Euclides."""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(e, m):
    """Calcula o inverso modular de e (mod m)."""
    d, x, y = extended_gcd(e, m)
    if d != 1:
        raise ValueError("O inverso modular não existe")
    return x % m

# --- Geração e Serialização de Chaves RSA ---

def generate_rsa_keys(bits=2048):
    """
    Gera um par de chaves RSA (pública e privada).
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    # Usando o totiente de Carmichael: lambda(n) = mmc(p-1, q-1)
    lambda_n = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    
    e = 65537 # Expoente público comum

    d = mod_inverse(e, lambda_n)

    # public_key = (e, n), private_key = (d, n)
    return ((e, n), (d, n))

def save_key_to_pem(key_data, filename, key_type):
    """Salva a chave em um formato similar ao PEM."""
    e_or_d, n = key_data
    
    e_or_d_b64 = base64.b64encode(e_or_d.to_bytes((e_or_d.bit_length() + 7) // 8, 'big')).decode('ascii')
    n_b64 = base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).decode('ascii')
    
    pem_content = f"-----BEGIN RSA {key_type.upper()} KEY-----\n"
    pem_content += f"{e_or_d_b64}:{n_b64}\n"
    pem_content += f"-----END RSA {key_type.upper()} KEY-----"
    
    with open(filename, 'w') as f:
        f.write(pem_content)

def load_key_from_pem(filename):
    """Carrega uma chave de um arquivo no nosso formato PEM."""
    with open(filename, 'r') as f:
        lines = f.readlines()
        
    # Remove os cabeçalhos e rodapés
    base64_data = lines[1].strip()
    e_or_d_b64, n_b64 = base64_data.split(':')
    
    e_or_d = int.from_bytes(base64.b64decode(e_or_d_b64), 'big')
    n = int.from_bytes(base64.b64decode(n_b64), 'big')
    
    return (e_or_d, n)


# --- Funções de Hash e PSS ---

HASH_FUNC = hashlib.sha3_256
SALT_LEN = HASH_FUNC().digest_size

def mgf1(seed, mask_len, hash_func=HASH_FUNC):
    """Mask Generation Function 1."""
    h_len = hash_func().digest_size
    if mask_len > (2**32) * h_len:
        raise ValueError("Máscara muito longa")
    
    T = b""
    for i in range(math.ceil(mask_len / h_len)):
        C = i.to_bytes(4, 'big')
        T += hash_func(seed + C).digest()
        
    return T[:mask_len]

def pss_encode(message, key_bits, salt_len=SALT_LEN, hash_func=HASH_FUNC):
    """
    Implementa o padding PSS (codificação) para uma assinatura.
    RFC 8017, Seção 9.1.1.
    """
    m_hash = hash_func(message).digest()
    h_len = len(m_hash)
    em_len = math.ceil((key_bits - 1) / 8)

    if em_len < h_len + salt_len + 2:
        raise ValueError("Erro de codificação: mensagem muito longa")

    salt = os.urandom(salt_len)
    
    M_prime = b'\x00' * 8 + m_hash + salt
    H = hash_func(M_prime).digest()
    
    PS = b'\x00' * (em_len - salt_len - h_len - 2)
    DB = PS + b'\x01' + salt
    
    db_mask = mgf1(H, em_len - h_len - 1, hash_func)
    
    masked_db = bytes(a ^ b for a, b in zip(DB, db_mask))
    
    # Zera os bits não utilizados no primeiro byte
    mask = 0xFF >> (8 * em_len - (key_bits - 1))
    masked_db = bytes([masked_db[0] & mask]) + masked_db[1:]
    
    EM = masked_db + H + b'\xbc'
    return EM

def pss_verify(message, encoded_message, key_bits, salt_len=SALT_LEN, hash_func=HASH_FUNC):

    m_hash = hash_func(message).digest()
    h_len = len(m_hash)
    em_len = math.ceil((key_bits - 1) / 8)

    if em_len < h_len + salt_len + 2:
        return False # Consistência da verificação

    if encoded_message[-1] != 0xbc:
        return False # Trailer incorreto

    masked_db = encoded_message[:em_len - h_len - 1]
    H = encoded_message[em_len - h_len - 1:-1]

    # Verifica os bits não utilizados
    if (masked_db[0] >> (8 - (8 * em_len - (key_bits - 1)))) != 0:
        return False
        
    db_mask = mgf1(H, em_len - h_len - 1, hash_func)
    DB = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # Zera novamente os bits não utilizados no DB recuperado
    mask = 0xFF >> (8 * em_len - (key_bits - 1))
    DB = bytes([DB[0] & mask]) + DB[1:]

    # Parse DB
    ps_len = em_len - h_len - salt_len - 2
    if not DB[:ps_len] == b'\x00' * ps_len:
        return False
    
    if DB[ps_len] != 0x01:
        return False

    salt = DB[ps_len + 1:]
    
    M_prime = b'\x00' * 8 + m_hash + salt
    H_prime = hash_func(M_prime).digest()

    return H == H_prime


# --- Funções de Assinatura e Verificação ---

def sign_message(message_bytes, private_key):
    """Cria uma assinatura RSA-PSS para uma mensagem."""
    d, n = private_key
    key_bits = n.bit_length()
    
    encoded_message = pss_encode(message_bytes, key_bits)
    em_int = int.from_bytes(encoded_message, 'big')
    
    # Cifra com a chave privada (assinatura)
    signature_int = pow(em_int, d, n)
    
    signature_bytes = signature_int.to_bytes((n.bit_length() + 7) // 8, 'big')
    return signature_bytes

def verify_signature(message_bytes, signature_bytes, public_key):
    """Verifica uma assinatura RSA-PSS."""
    e, n = public_key
    key_bits = n.bit_length()
    
    signature_int = int.from_bytes(signature_bytes, 'big')
    
    # Decifra com a chave pública
    em_int = pow(signature_int, e, n)
    
    em_len = math.ceil((key_bits - 1) / 8)
    encoded_message = em_int.to_bytes(em_len, 'big')

    return pss_verify(message_bytes, encoded_message, key_bits)