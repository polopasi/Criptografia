import cryptography
import base64 
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from RSA_Lab_25 import rsa_key


def extraer_clave_pub(Certificado):
    cert = x509.load_pem_x509_certificate(Certificado, default_backend())
    return cert.public_key()

def comprobante_voto(Rebut, Codi, Certificado):
    """
    Entrada:
    Rebut: String de longitud 10
    Codi: String formado por la concatenaci´on de 5 partes usando # como separador,
    podr´ıa contener espacios y saltos de l´ıneas que deben ser eliminados.
    Certificado: Fichero que contiene el certificado, en formato PEM, con la clave
    p´ublica del firmante del comprobante de votaci´on.
    Salida: un entero cuyo valor ser´a
    0 si el Rebut y la firma del Codi son correctos,
    1 si el Rebut es incorrecto pero la firma del Codi es correcta,
    2 si el Rebut es correcto pero la firma del Codi es incorrecta,
    3 si ni el Rebut ni la firma del Codi son correctos.
    """

    firma_correcta = True
    rebut_correcte = True

    noSpace_Codi = Codi.replace("\n", "")
    control_code_pieces = noSpace_Codi.split('#')

    # (1))
    ballotId = base64.b64decode(control_code_pieces[1])
    VI = base64.b64encode(hashlib.sha256(hashlib.sha256(ballotId).digest()).digest())

    # (2)
    SD = VI + b';'+ control_code_pieces[2].encode() + b';' + control_code_pieces[3].encode() + b';' + control_code_pieces[4].encode()

    # (3)
    signature = base64.b64decode(control_code_pieces[0])

    # (4)
    clave_publica_firmante = extraer_clave_pub(Certificado)


    try:
        clave_publica_firmante.verify(
            signature,
            SD,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        firma_correcta = True
    except InvalidSignature:
        firma_correcta = False

    # bloque de cuando usaba mi propia verify, descomentar para usarlo
    """
    rsax = rsa_key(public_numbers.n.bit_length(), public_numbers.e, public_numbers.n)
    
    # paso de bytes a enteros
    SD_int = int.from_bytes(SD, 'big')
    signature_int = int.from_bytes(signature, 'big')

    if not rsax.verify(SD_int, signature_int):
        firma_correcta = False
    else: 
        firma_correcta = True       # no cambia nada ya que el valor inicial de firma_correcta = True
    """

    # validando el recibo
    RR = base64.b64encode(hashlib.sha256(ballotId).digest())
    if Rebut != RR[:len(Rebut)].decode():
        rebut_correcte = False
        if not rebut_correcte and not firma_correcta:
            return 3
        if not rebut_correcte and firma_correcta:
            return 1
    else:
        rebut_correcte = True               # no cambia nada ya que valor inicial de rebut_correcte = True
        if rebut_correcte and not firma_correcta:
            return 2

    return 0                                # si llegamos aqui es que tanto el Rebut como la Firma son correctas

"""
with open("message_server.pem", "rb") as f:
    pem= f.read()
codi = "AklTUamCVK4urY+1fO0fBtHz7CYt1RE80A/xju/qlkKPkj5gUxZ2NNzO7FuU1a1dGztjGJvB3oAfLw6rpAMWNgOc+W+pOmun8vCEiEuAzPWmflr1ACVRBSoC/vioEDJ8zoVtzJWEv9a+4vmaxRxaZzZoGFiN7nNscvJXgqU4pvILQO3VWUve6JJ65KVrAbxRM8bkBshy3yMGjXLVpZDSsKOwjTYGArsZuX43ITQxbpuitqBujKSw54De1QDJbv8SGol9aLSMpmZ3O/M1PgjAAf1HWWjzKlunmzv9LDIoh/nLRU6+3a8CWZ9L5SfV8/MSHQqfHbXJZd9ZcMBvso4NkA==#0R0En5w1t0cSTjAbvyOgM/9plEpkY3C+#40289dc597e9c1fa0199c2cdf129137c#40289dc597e9c1fa0199c2cdf11c1375#1760076542676"
print(comprobante_voto("iVoIkFePBM", codi, pem))
"""