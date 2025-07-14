# Trabalho_Pratico3
# Gerador e Verificador de Assinaturas RSA-PSS

Este projeto é uma implementação em Python puro para gerar e verificar assinaturas digitais usando o padrão RSA-PSS. A restrição principal é não usar bibliotecas criptográficas de alto nível para as primitivas RSA, como geração de chaves.

## Estrutura do Projeto

- `main.py`: Ponto de entrada principal que executa o fluxo de demonstração.
- `src/`: Contém o código-fonte modularizado.
  - `rsa_core.py`: Implementação do Teste de Miller-Rabin e geração de chaves RSA.
  - `pss_padding.py`: Implementação do padding PSS, incluindo a função MGF1.
  - `formatador.py`: Funções para salvar e carregar as chaves no formato PEM/Base64.
  - `logica_assinatura.py`: Orquestra o processo de assinatura e verificação, unindo os outros módulos.
- `chaves/`: Diretório padrão para armazenar as chaves geradas.
- `arquivos_para_assinar/`: Diretório para colocar os arquivos que serão assinados.
- `assinaturas_geradas/`: Diretório padrão para salvar as assinaturas criadas.

## Como Usar

1. Certifique-se de ter o Python 3.8+ instalado.
2. Clone ou baixe este repositório.
3. Execute o script principal a partir do diretório raiz do projeto:

   ```bash
   python main.py