import sys
from aes_Lab_25 import AES

def main():
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-c':
            modo = 'cifrar'
        elif sys.argv[i] == '-d':
            modo = 'descifrar'
        elif sys.argv[i] == '-f':
            archivo = sys.argv[i + 1]
        elif sys.argv[i] == '-p':
            polinomio = sys.argv[i + 1]
        elif sys.argv[i] == '-k':
            key = sys.argv[i + 1]
        i += 1

    polinomio = int(polinomio, 16)
    # elimino el '0x' de la key para evitar errores
    key = bytearray.fromhex(key[2:])

    aes = AES(key, polinomio)

    if modo == 'cifrar':
        aes.encrypt_file(archivo)
    elif modo == 'descifrar':
        aes.decrypt_file(archivo)

if __name__ == "__main__":
    main()