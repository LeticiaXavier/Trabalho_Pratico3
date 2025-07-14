# Arquivo: main.py

import os
import hashlib

# Importa as funcionalidades dos nossos módulos na pasta src/
from src.rsa_core import generate_keys
from src.formatador import save_key
from src.logica_assinatura import AssinadorPSS

# --- Configurações e Constantes ---
# O trabalho pede no mínimo 1024 bits, mas recomenda 2048 para maior segurança.
KEY_SIZE_BITS = 2048

# Define os nomes dos diretórios para organização
DIR_CHAVES = "chaves"
DIR_ARQUIVOS = "arquivos_para_assinar"
DIR_ASSINATURAS = "assinaturas_geradas"

# Cria os caminhos completos para os arquivos que serão gerados/usados
PUBLIC_KEY_FILE = os.path.join(DIR_CHAVES, "chave_publica.pem")
PRIVATE_KEY_FILE = os.path.join(DIR_CHAVES, "chave_privada.pem")

NOME_ARQUIVO_EXEMPLO = "documento_exemplo.txt"
FILE_TO_SIGN = os.path.join(DIR_ARQUIVOS, NOME_ARQUIVO_EXEMPLO)
SIGNATURE_FILE = os.path.join(DIR_ASSINATURAS, f"{NOME_ARQUIVO_EXEMPLO}.sig")

def setup_directories():
    """Cria os diretórios necessários para o projeto se eles não existirem."""
    os.makedirs(DIR_CHAVES, exist_ok=True)
    os.makedirs(DIR_ARQUIVOS, exist_ok=True)
    os.makedirs(DIR_ASSINATURAS, exist_ok=True)

def main():
    """
    Função principal que executa o fluxo de demonstração do programa de
    geração e verificação de assinaturas digitais.
    """
    print("Iniciando o programa Gerador/Verificador de Assinaturas RSA-PSS...")
    setup_directories()
    
    # Instancia o assinador, que usará o algoritmo SHA-3 conforme pedido no trabalho[cite: 14].
    assinador = AssinadorPSS(hash_algo=hashlib.sha3_256)

    # --- Parte 1: Geração de Chaves --- [cite: 9]
    print("\n--- ETAPA 1: GERAÇÃO DE CHAVES ---")
    # Para economizar tempo, só gera as chaves se os arquivos não existirem.
    if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
        public_key, private_key = generate_keys(KEY_SIZE_BITS)
        save_key(PUBLIC_KEY_FILE, public_key, "PUBLIC")
        save_key(PRIVATE_KEY_FILE, private_key, "PRIVATE")
    else:
        print("Arquivos de chave já existem. Pulando a etapa de geração.")
    
    # --- Parte 2: Assinatura de Arquivo --- 
    print("\n--- ETAPA 2: ASSINATURA DE DOCUMENTO ---")
    # Cria um arquivo de exemplo para assinar.
    with open(FILE_TO_SIGN, "w", encoding='utf-8') as f:
        f.write("Este é o conteúdo original do documento de teste.\n")
        f.write("A assinatura digital garante a autenticidade e a integridade deste texto.\n")
    print(f"Arquivo '{FILE_TO_SIGN}' criado para o teste.")
    
    # Realiza a assinatura do arquivo usando a chave privada.
    assinador.sign(PRIVATE_KEY_FILE, FILE_TO_SIGN, SIGNATURE_FILE)
    
    # --- Parte 3: Verificação de Assinatura --- 
    print("\n--- ETAPA 3: VERIFICAÇÃO (Cenário de Sucesso) ---")
    print(f"Verificando a assinatura '{SIGNATURE_FILE}' para o arquivo original...")
    assinador.verify(PUBLIC_KEY_FILE, FILE_TO_SIGN, SIGNATURE_FILE)
    
    # --- Cenário de Falha (Demonstração de Segurança) ---
    print("\n--- ETAPA 4: VERIFICAÇÃO (Cenário de Falha) ---")
    print(f"Modificando o arquivo '{FILE_TO_SIGN}' para invalidar a assinatura...")
    with open(FILE_TO_SIGN, "a", encoding='utf-8') as f:
        f.write("\n>>> LINHA ADICIONAL MALICIOSA: Esta linha invalida a assinatura anterior. <<<")
    
    print("Tentando verificar a assinatura novamente com o arquivo modificado...")
    assinador.verify(PUBLIC_KEY_FILE, FILE_TO_SIGN, SIGNATURE_FILE)

# Este é o padrão em Python para garantir que a função main() seja executada
# apenas quando o script é chamado diretamente.
if __name__ == "__main__":
    main()