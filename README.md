# Trabalho_Pratico3
# Gerador e Verificador de Assinaturas RSA-PSS

**Status do Projeto:** Concluído (Julho de 2025)

## Descrição

Este projeto é uma implementação completa de um sistema de geração e verificação de assinaturas digitais utilizando o algoritmo RSA com o esquema de preenchimento PSS (Probabilistic Signature Scheme). Todas as primitivas criptográficas essenciais, como a geração de chaves com o teste de primalidade de Miller-Rabin, a exponenciação modular e o padding PSS, foram implementadas manualmente em Python, sem o uso de bibliotecas criptográficas de alto nível para estas operações.

O sistema é operado via linha de comando e é capaz de assinar qualquer tipo de arquivo, garantindo sua **integridade** (prova de que não foi alterado) e **autenticidade** (prova de que foi assinado pelo detentor da chave privada).

## Funcionalidades

-   Geração de pares de chaves RSA com tamanhos de bits customizáveis (ex: 1024, 2048).
-   Assinatura digital de arquivos usando o padrão seguro RSA-PSS.
-   Verificação de assinaturas para validar a integridade e autoria de um arquivo.
-   Interface de linha de comando clara e intuitiva para todas as operações.

## Tecnologias Utilizadas

-   **Python 3.x**
-   Bibliotecas Nativas:
    -   `hashlib`: Para o cálculo de hash (SHA3-256).
    -   `argparse`: Para a interface de linha de comando.
    -   `base64`: Para a codificação de chaves e assinaturas.
    -   `os`: Para geração de números aleatórios seguros.

## Pré-requisitos

Para executar este projeto, você precisa apenas ter o **Python 3** instalado em seu sistema e configurado no PATH.

-   [Página oficial de download do Python](https://www.python.org/downloads/)

> **Nota para usuários Windows:** Se o comando `python` não for reconhecido no seu terminal, utilize o comando `py` em seu lugar.

## Como Usar

1.  **Clone ou baixe o repositório:**
    ```bash
    git clone [https://github.com/seu-usuario/seu-repositorio.git](https://github.com/seu-usuario/seu-repositorio.git)
    ```
    Ou simplesmente baixe os arquivos `assinador.py` e `crypto_lib.py` na mesma pasta.

2.  **Navegue até a pasta do projeto:**
    ```bash
    cd nome-da-pasta-do-projeto
    ```

3.  **Execute os Comandos:**

    O programa possui três comandos principais: `gerar`, `assinar` e `verificar`.

    ---

    ### **1. Gerar Chaves**
    Cria um par de chaves pública e privada e as salva em arquivos no formato PEM.

    **Comando:**
    ```bash
    py assinador.py gerar --pub <arquivo_chave_publica> --priv <arquivo_chave_privada> --bits <tamanho>
    ```
    -   `--pub`: Nome do arquivo para salvar a chave pública (ex: `publica.pem`).
    -   `--priv`: Nome do arquivo para salvar a chave privada (ex: `privada.pem`).
    -   `--bits`: (Opcional) Tamanho da chave em bits. Padrão: `2048`.

    ---

    ### **2. Assinar um Arquivo**
    Cria uma assinatura digital para um arquivo usando uma chave privada.

    **Comando:**
    ```bash
    py assinador.py assinar --priv <arquivo_chave_privada> --arq <arquivo_para_assinar> --sig <arquivo_de_saida_da_assinatura>
    ```
    -   `--priv`: Caminho para sua chave privada (ex: `privada.pem`).
    -   `--arq`: Arquivo que você deseja assinar (ex: `documento.txt`).
    -   `--sig`: Nome do arquivo onde a assinatura será salva (ex: `documento.sig`).

    ---

    ### **3. Verificar uma Assinatura**
    Verifica se uma assinatura é válida para um determinado arquivo usando a chave pública correspondente.

    **Comando:**
    ```bash
    py assinador.py verificar --pub <arquivo_chave_publica> --arq <arquivo_original> --sig <arquivo_da_assinatura>
    ```
    -   `--pub`: Caminho para a chave pública (ex: `publica.pem`).
    -   `--arq`: O arquivo original que foi assinado (ex: `documento.txt`).
    -   `--sig`: O arquivo de assinatura correspondente (ex: `documento.sig`).

## Exemplo de Fluxo Completo

```bash
# Passo 0: Crie um arquivo de exemplo para assinar
echo "Este e um documento secreto." > meu_arquivo.txt

# Passo 1: Gere um par de chaves de 2048 bits
py assinador.py gerar --pub publica.pem --priv privada.pem --bits 2048
# Resultado: Arquivos publica.pem e privada.pem sao criados.

# Passo 2: Assine o arquivo usando a chave privada
py assinador.py assinar --priv privada.pem --arq meu_arquivo.txt --sig meu_arquivo.sig
# Resultado: Arquivo meu_arquivo.sig e criado.

# Passo 3: Verifique a assinatura com a chave publica
py assinador.py verificar --pub publica.pem --arq meu_arquivo.txt --sig meu_arquivo.sig
# Resultado esperado: ASSINATURA VÁLIDA.

# Passo 4: Altere o arquivo original para simular uma adulteracao
echo "Este texto foi alterado." > meu_arquivo.txt

# Passo 5: Tente verificar a assinatura novamente
py assinador.py verificar --pub publica.pem --arq meu_arquivo.txt --sig meu_arquivo.sig
# Resultado esperado: ASSINATURA INVÁLIDA!
