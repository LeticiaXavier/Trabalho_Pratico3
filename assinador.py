
import argparse
import base64
from crypto_lib import (
    generate_rsa_keys,
    save_key_to_pem,
    load_key_from_pem,
    sign_message,
    verify_signature
)

def main():
    parser = argparse.ArgumentParser(description="Gerador/Verificador de Assinaturas RSA-PSS.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Comandos disponíveis")

    # Comando para gerar chaves
    parser_gen = subparsers.add_parser("gerar", help="Gera um par de chaves RSA.")
    parser_gen.add_argument("--pub", required=True, help="Arquivo para salvar a chave pública (ex: public.pem).")
    parser_gen.add_argument("--priv", required=True, help="Arquivo para salvar a chave privada (ex: private.pem).")
    parser_gen.add_argument("--bits", type=int, default=2048, help="Tamanho da chave em bits (padrão: 2048).")

    # Comando para assinar um arquivo
    parser_sign = subparsers.add_parser("assinar", help="Assina um arquivo usando uma chave privada.")
    parser_sign.add_argument("--priv", required=True, help="Arquivo da chave privada (private.pem).")
    parser_sign.add_argument("--arq", required=True, help="Arquivo a ser assinado.")
    parser_sign.add_argument("--sig", required=True, help="Arquivo de saída para a assinatura (ex: doc.sig).")

    # Comando para verificar uma assinatura
    parser_verify = subparsers.add_parser("verificar", help="Verifica a assinatura de um arquivo.")
    parser_verify.add_argument("--pub", required=True, help="Arquivo da chave pública (public.pem).")
    parser_verify.add_argument("--arq", required=True, help="Arquivo original que foi assinado.")
    parser_verify.add_argument("--sig", required=True, help="Arquivo da assinatura a ser verificada (doc.sig).")
    
    args = parser.parse_args()

    if args.command == "gerar":
        print(f"Gerando par de chaves RSA de {args.bits} bits... Isso pode levar um momento.")
        public_key, private_key = generate_rsa_keys(args.bits)
        save_key_to_pem(public_key, args.pub, "PUBLIC")
        save_key_to_pem(private_key, args.priv, "PRIVATE")
        print(f"Chaves salvas em '{args.pub}' e '{args.priv}'.")

    elif args.command == "assinar":
        print(f"Carregando chave privada de '{args.priv}'...")
        private_key = load_key_from_pem(args.priv)
        
        try:
            with open(args.arq, 'rb') as f:
                message_bytes = f.read()
        except FileNotFoundError:
            print(f"Erro: O arquivo '{args.arq}' não foi encontrado.")
            return

        print(f"Assinando o arquivo '{args.arq}'...")
        signature_bytes = sign_message(message_bytes, private_key)
        
        # Salva a assinatura em Base64
        with open(args.sig, 'w') as f:
            f.write(base64.b64encode(signature_bytes).decode('ascii'))
        
        print(f"Assinatura salva em '{args.sig}'.")

    elif args.command == "verificar":
        print(f"Carregando chave pública de '{args.pub}'...")
        public_key = load_key_from_pem(args.pub)

        try:
            with open(args.arq, 'rb') as f:
                message_bytes = f.read()
        except FileNotFoundError:
            print(f"Erro: O arquivo original '{args.arq}' não foi encontrado.")
            return
            
        try:
            with open(args.sig, 'r') as f:
                signature_b64 = f.read()
            signature_bytes = base64.b64decode(signature_b64)
        except FileNotFoundError:
            print(f"Erro: O arquivo de assinatura '{args.sig}' não foi encontrado.")
            return
        except (ValueError, TypeError):
             print(f"Erro: O arquivo de assinatura '{args.sig}' não está em formato Base64 válido.")
             return

        print(f"Verificando a assinatura de '{args.arq}' com a assinatura '{args.sig}'...")
        is_valid = verify_signature(message_bytes, signature_bytes, public_key)
        
        if is_valid:
            print("\nResultado: ASSINATURA VÁLIDA.")
            print("O arquivo não foi modificado e a assinatura corresponde à chave pública.")
        else:
            print("\nResultado: ASSINATURA INVÁLIDA!")
            print("O arquivo pode ter sido alterado ou a assinatura não corresponde à chave pública.")

if __name__ == "__main__":
    main()