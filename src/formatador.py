# Arquivo: src/formatador.py

import base64

def save_key(filename, key, key_type):
    """
    Salva uma chave (pública ou privada) em um arquivo formatado em Base64.
    
    Esta função implementa o requisito da Parte 1-b do trabalho.

    Args:
        filename (str): O caminho do arquivo onde a chave será salva.
        key (tuple): A chave a ser salva, no formato (n, e) ou (n, d).
        key_type (str): O tipo da chave, para ser usado no cabeçalho (ex: "PUBLIC" ou "PRIVATE").
    """
    n, val = key
    
    # 1. Serialização: Converter os números 'n' e 'val' (e ou d) em bytes.
    #    Para saber onde um número termina e o outro começa, usamos um separador.
    #    Um caractere simples como '|' é suficiente para essa finalidade.
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    
    key_data = n_bytes + b'|' + val_bytes
    
    # 2. Codificação: Codificar os bytes resultantes em Base64.
    b64_data = base64.b64encode(key_data).decode('ascii')

    # 3. Formatação (estilo PEM): Criar os cabeçalhos e rodapés.
    header = f"-----BEGIN {key_type.upper()} KEY-----"
    footer = f"-----END {key_type.upper()} KEY-----"

    # 4. Salvar no arquivo.
    with open(filename, 'w') as f:
        f.write(header + '\n')
        f.write(b64_data + '\n')
        f.write(footer + '\n')
    print(f"Chave salva em: {filename}")

def load_key(filename):
    """
    Carrega uma chave de um arquivo formatado em Base64.

    Args:
        filename (str): O caminho do arquivo da chave.

    Returns:
        tuple: A chave carregada como uma tupla de inteiros (n, val).
    """
    # 1. Ler o arquivo, ignorando cabeçalhos e rodapés.
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    b64_data = "".join(line.strip() for line in lines if not line.startswith("-----"))
    
    # 2. Decodificação: Decodificar a string Base64 para bytes.
    key_data = base64.b64decode(b64_data)
    
    # 3. Deserialização: Separar os bytes de 'n' e 'val' usando o separador.
    n_bytes, val_bytes = key_data.split(b'|')
    
    # 4. Converter os bytes de volta para inteiros.
    n = int.from_bytes(n_bytes, 'big')
    val = int.from_bytes(val_bytes, 'big')
    
    return (n, val)