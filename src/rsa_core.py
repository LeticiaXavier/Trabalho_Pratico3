import secrets
import math

def is_prime(n, k=40):
    """
    Teste de primalidade de Miller-Rabin.
    
    Verifica se um número 'n' é provavelmente primo realizando o teste 'k' vezes.
    Para aplicações criptográficas, k=40 oferece um nível de confiança muito alto.

    Args:
        n (int): O número a ser testado.
        k (int): O número de iterações do teste.

    Returns:
        bool: True se n for provavelmente primo, False caso contrário.
    """
    # Casos base: números menores que 2 não são primos.
    if n < 2:
        return False
    # 2 e 3 são primos.
    if n == 2 or n == 3:
        return True
    # Números pares (exceto 2) não são primos.
    if n % 2 == 0:
        return False

    # Escreve n-1 na forma 2^r * d, onde d é ímpar.
    # Esta decomposição é central para o teste de Miller-Rabin.
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Executa o teste de primalidade k vezes para alta confiança.
    for _ in range(k):
        # Escolhe uma base aleatória 'a' no intervalo [2, n-2].
        a = secrets.randbelow(n - 3) + 2
        
        # Calcula x = a^d mod n.
        x = pow(a, d, n)
        
        # Se x for 1 ou n-1, o número pode ser primo, então passamos para a próxima iteração.
        if x == 1 or x == n - 1:
            continue

        # Realiza o teste das raízes quadradas.
        # Se nenhuma das potências sucessivas de x resultar em n-1, n é composto.
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break  # Encontrou uma raiz quadrada não trivial de 1, pode ser primo.
        else:
            # Se o loop terminar sem encontrar n-1, n é definitivamente composto.
            return False
            
    # Se n passou em todos os k testes, é muito provável que seja primo.
    return True

def generate_prime(bits):
    """
    Gera um número primo com a quantidade de bits especificada.

    Args:
        bits (int): A quantidade de bits que o número primo deve ter (e.g., 1024).

    Returns:
        int: Um número provavelmente primo com a quantidade de bits correta.
    """
    while True:
        # 1. Gera um número aleatório com a quantidade de bits desejada.
        p = secrets.randbits(bits)
        
        # 2. Garante que o número tenha exatamente 'bits' de comprimento e seja ímpar.
        #    - `p |= (1 << bits - 1)`: Define o bit mais significativo como 1.
        #    - `p |= 1`: Define o bit menos significativo como 1 (garante que seja ímpar).
        p |= (1 << bits - 1) | 1
        
        # 3. Testa se o número gerado é primo.
        if is_prime(p):
            return p

def generate_keys(key_bits=2048):
    """
    Gera um par de chaves pública e privada RSA.

    Args:
        key_bits (int): O tamanho total da chave RSA em bits (e.g., 2048).

    Returns:
        tuple: Uma tupla contendo (public_key, private_key),
               onde cada chave é uma tupla (n, e) ou (n, d).
    """
    print(f"Gerando chaves RSA de {key_bits} bits... Isso pode levar alguns segundos.")
    
    # O expoente público 'e' é comumente escolhido como 65537 por ser primo e
    # eficiente para exponenciação (tem apenas dois bits '1' em sua representação binária).
    e = 65537
    
    # A geração dos primos p e q ocorre em um loop para garantir que
    # p e q sejam diferentes e que mdc(e, phi_n) seja 1.
    while True:
        # Gera dois primos, cada um com metade do tamanho da chave final.
        p = generate_prime(key_bits // 2)
        q = generate_prime(key_bits // 2)
        
        if p == q:
            continue

        n = p * q
        phi_n = (p - 1) * (q - 1)  # Função totiente de Euler

        # Verifica se 'e' é coprimo com phi_n. Se não for, outras chaves devem ser geradas.
        if math.gcd(e, phi_n) == 1:
            break
            
    # Calcula o expoente privado 'd' como o inverso multiplicativo modular de 'e' mod phi_n.
    # d * e ≡ 1 (mod phi_n)
    d = pow(e, -1, phi_n)
    
    # Define as chaves
    public_key = (n, e)
    private_key = (n, d)
    
    print("Chaves geradas com sucesso.")
    return public_key, private_key