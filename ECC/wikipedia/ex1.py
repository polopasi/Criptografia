from sympy.ntheory import isprime
from ecpy.curves import Curve, Point
from ecpy.ecdsa import ECDSA
from ecpy.keys import ECPublicKey
import hashlib



# EL PAQUETE CLIENT HELLO DE WWW.WIKIPEDIA.ORG ES EL NUMERO 294
# EL PAQUETE SERVER HELLO, ENCRYPTED DE WWW.WIKIPEDIA.ORG ES EL NUMERO 300
# EL PAQUETE CERTIFICATE, CERTIFICATE VERIFY DE WWW.WIKIPEDIA.ORG ES EL NUMERO 304
# EL FICHERO PARA DESCIFRAR LOS PAQUETES ES TLS_keys_descifrar_wikipedia.txt

# la curva tiene un orden n_curva_wireshark: (copiado directamente de wireshark)
n_curva_wireshark = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
print(f"El orden es un numero primo? {isprime(n_curva_wireshark)}")

# la clave publica P tiene el valor:
# 040ac786b1a74840785d4a2d8e0f1f2fd9b28f48abd0227136816c1a9acc9705339646171d75707156a95b0dbd4f683879d49bf9cdce11de7db82b4c2e001fbe43
prefijoInicial = 0x04
P_x = 0x0ac786b1a74840785d4a2d8e0f1f2fd9b28f48abd0227136816c1a9acc970533
P_y = 0x9646171d75707156a95b0dbd4f683879d49bf9cdce11de7db82b4c2e001fbe43

# la curva P-256 es de la forma
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

print (f"El punto pertenece a la curva (cumple y**2 = x**3 + ax + b   mod p)? {((P_y**2) % p) == ((P_x ** 3) + (a * P_x) + b) % p}")
curve = Curve.get_curve('secp256r1')
P = Point(P_x, P_y, curve)
print(f"El punto pertenece a la curva (comprobacion ecpy)? {curve.is_on_curve(P)}")

# el orden del punto es el mismo que el de la curva, la comprobacion es que P * n_curva_wireshark da infinito
print(f"El orden del punto P n_punto = n_curva_wireshark (P * n = INF)? {n_curva_wireshark * P ==curve.infinity}")

# COMPROBACION FIRMA

clave_publica = ECPublicKey(P)

with open("certificate_verify.bin", "rb") as f:
    firma_certificate_verify = f.read()
# concat es #> cat client_hello.bin server_hello.bin encrypted.bin certificate.bin > content_be_signed.bin
with open("content_be_signed.bin", "rb") as f:
    concat = f.read()
hash_concat = hashlib.sha256(concat).digest()

mess = (b"\x20" * 64) + b"TLS 1.3, server CertificateVerify" + b"\x00" + hash_concat

hash_mess = hashlib.sha256(mess).digest()

ecdsa = ECDSA("DER")
valid = ecdsa.verify(hash_mess, firma_certificate_verify,  clave_publica)
print("Firma valida:", valid)


