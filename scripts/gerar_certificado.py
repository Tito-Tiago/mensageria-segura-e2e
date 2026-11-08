"""Execute da raiz: python -m scripts.gerar_certificado"""
import argparse

from src.server.identity import ServerIdentity


def main():
    parser = argparse.ArgumentParser(description='Gera identidade RSA local sem sobrescrever arquivos.')
    parser.add_argument('--key', default='certs/server.key')
    parser.add_argument('--cert', default='certs/server.crt')
    args = parser.parse_args()
    try:
        ServerIdentity.generate().save(args.key, args.cert)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Não foi possível criar a identidade: {exc}\n')
    print('Identidade criada. Distribua somente o certificado público por canal confiável.')


if __name__ == '__main__':
    main()
