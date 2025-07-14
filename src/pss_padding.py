# Arquivo: src/pss_padding.py

import secrets
import hashlib # Necessário para obter o tamanho do hash e a função em si como argumento

def mgf1(seed_bytes, mask_len, hash_algo):
    """
    Mask Generation Function (MGF1), conforme especificado no padrão PKCS #1.

    Gera uma "máscara" (uma sequência de bytes pseudoaleatória) de um tamanho
    desejado a partir de uma semente. É um componente crucial do PSS.

    Args:
        seed_bytes (bytes): A semente a partir da qual a máscara é gerada.
        mask_len (int): O comprimento desejado da máscara em bytes.
        hash_algo: A função de hash a ser usada (ex: hashlib.sha3_256).

    Returns:
        bytes: A máscara gerada com o comprimento 'mask_len'.
    """
    h_len = hash_algo().digest_size
    mask = b''
    # O loop executa ceil(mask_len / h_len) vezes.
    counter = 0
    while len(mask) < mask_len:
        # Converte o contador para uma string de 4 bytes.
        C = counter.to_bytes(4, 'big')
        # Concatena a semente com o contador e calcula o hash.
        mask += hash_algo(seed_bytes + C).digest()
        counter += 1
    # Retorna apenas a quantidade de bytes necessária.
    return mask[:mask_len]

def pss_encode(m_hash, em_bits, hash_algo, h_len, s_len):
    """
    Implementa o esquema de codificação EMSA-PSS-ENCODE.

    Esta função prepara o hash da mensagem para a assinatura RSA.
    Atende diretamente ao requisito da Parte 2-b do trabalho.

    Args:
        m_hash (bytes): O hash da mensagem a ser assinada.
        em_bits (int): O tamanho em bits da mensagem codificada final (geralmente n.bit_length() - 1).
        hash_algo: A função de hash sendo utilizada.
        h_len (int): O comprimento em bytes do hash.
        s_len (int): O comprimento desejado para o salt em bytes.

    Returns:
        bytes: A mensagem codificada (EM), pronta para a exponenciação RSA.
    """
    em_len = (em_bits + 7) // 8
    
    # 1. Verificação de comprimento
    if em_len < h_len + s_len + 2:
        raise ValueError("Tamanho da codificação muito pequeno.")
    
    # 2. Gera um salt aleatório
    salt = secrets.token_bytes(s_len)
    
    # 3. Constrói o bloco M' = (8 bytes nulos) || m_hash || salt
    m_prime = b'\x00' * 8 + m_hash + salt
    
    # 4. Calcula o hash de M' para obter H'
    H_prime = hash_algo(m_prime).digest()
    
    # 5. Gera o bloco de preenchimento PS
    ps_len = em_len - s_len - h_len - 2
    PS = b'\x00' * ps_len
    
    # 6. Constrói o bloco de dados DB = PS || 0x01 || salt
    DB = PS + b'\x01' + salt
    
    # 7. Gera a máscara db_mask usando MGF1 com H' como semente
    db_mask = mgf1(H_prime, em_len - h_len - 1, hash_algo)
    
    # 8. Realiza a operação XOR para obter o maskedDB
    masked_db = bytes(a ^ b for a, b in zip(DB, db_mask))
    
    # 9. Zera os bits não utilizados no primeiro byte de maskedDB
    bits_sobrando = 8 * em_len - em_bits
    if bits_sobrando > 0:
        mask = (1 << (8 - bits_sobrando)) - 1
        masked_db = bytes([masked_db[0] & mask]) + masked_db[1:]
    
    # 10. Constrói a mensagem final EM = maskedDB || H' || 0xbc
    return masked_db + H_prime + b'\xbc'

def pss_verify(m_hash, em, em_bits, hash_algo, h_len, s_len):
    """
    Implementa o esquema de verificação EMSA-PSS-VERIFY.

    Esta função é usada na Parte 3 [cite: 20] para validar a mensagem decifrada
    e confirmar se o hash corresponde ao do arquivo original.

    Args:
        m_hash (bytes): O hash da mensagem original (recalculado).
        em (bytes): A mensagem codificada, recuperada após a decifração da assinatura.
        em_bits (int): O tamanho em bits da mensagem codificada.
        hash_algo: A função de hash utilizada.
        h_len (int): O comprimento do hash.
        s_len (int): O comprimento do salt.

    Returns:
        bool: True se a verificação for bem-sucedida, False caso contrário.
    """
    em_len = (em_bits + 7) // 8

    # 1. Verificações de consistência
    if em_len < h_len + s_len + 2: return False
    if em[-1] != 0xbc: return False

    # 2. Separa maskedDB e H'
    masked_db = em[:em_len - h_len - 1]
    H_prime = em[em_len - h_len - 1 : -1]

    # 3. Verifica os bits não utilizados
    bits_sobrando = 8 * em_len - em_bits
    if bits_sobrando > 0 and (masked_db[0] >> (8 - bits_sobrando)) != 0:
        return False

    # 4. Gera a máscara db_mask da mesma forma que na codificação
    db_mask = mgf1(H_prime, em_len - h_len - 1, hash_algo)
    
    # 5. Desfaz o XOR para recuperar o bloco DB
    DB = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    
    # 6. Zera os bits não utilizados em DB
    if bits_sobrando > 0:
        mask = (1 << (8 - bits_sobrando)) - 1
        DB = bytes([DB[0] & mask]) + DB[1:]

    # 7. Verifica o padding (zeros) e o separador 0x01
    ps_len = em_len - h_len - s_len - 2
    if not all(b == 0 for b in DB[:ps_len]): return False
    if DB[ps_len] != 0x01: return False
            
    # 8. Extrai o salt
    salt = DB[len(DB) - s_len:]
    
    # 9. Recalcula H' usando o hash da mensagem original e o salt extraído
    m_prime_verify = b'\x00' * 8 + m_hash + salt
    H_prime_verify = hash_algo(m_prime_verify).digest()
    
    # 10. Compara os hashes. Use compare_digest para evitar "timing attacks".
    return secrets.compare_digest(H_prime, H_prime_verify)