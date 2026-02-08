import hashlib
import math
import random
import base64 

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes



class rsa_key:

    # funciones para generar primos, funciones cogidas de los notebooks de clase
    def is_prime(self, n):
        if n == 2 or n == 3: return True
        if n < 2 or n%2 == 0: return False
        if n < 9: return True
        if n%3 == 0: return False
        r = int(math.isqrt(n))
        f = 5
        while f <= r:
            if n % f == 0: return False
            if n % (f+2) == 0: return False
            f += 6
        return True   

    def es_divisible(self, n, lista_primos):
        for i in lista_primos:
            if n%i == 0:
                return True
        return False

    def Test_Miller_Rabin(self, n,b):
        if math.gcd(n,b) != 1:
            return None

        n1 = n-1
        t = 0
        while n1:
            if n1 & 1:
                break
            n1 >>= 1
            t += 1
        n0 = int((n-1) // 2**t)

        x_i = int(pow(b, n0, n))
        if x_i == 1 or x_i == n-1:
            return True
        else:
            for _ in range(t):
                x_i = int(pow(x_i, 2, n))
                if x_i == n-1:
                    return True
        return False


    def Test_Miller_Rabin_bases(self, n, k = 10):
        for _ in range(k):
            base = random.randint(2, n-1)
            if math.gcd(base, n) != 1:
                return False
            if self.Test_Miller_Rabin(n, base) == False:
                return False
        return True


    def Primo_probable(self, n_bits, lista_primos, k = 10):
        n = 2*random.randint(2**(n_bits-2), 2**(n_bits-1))+1
        aux = 0
        aux1 = 0
        while self.es_divisible(n, lista_primos) == True or self.Test_Miller_Rabin(n, 2) == False or self.Test_Miller_Rabin_bases(n, k = 10) == False:
            n = n+2
            aux = aux+1
            if aux > n_bits//2:
                n = 2*random.randint(2**(n_bits-2), 2**(n_bits-1))+1
                aux = 0
                aux1 += 1
        return n



    # INIT
    def __init__(self, bits_modulo, e):
        """
        genera una clave RSA (de 2048 bits y exponente p´ublico 2**16+1 por defecto)
        """
        lista_primos = [i for i in range(256) if self.is_prime(i)]
        self.publicExponent = e 
        bitsPrimo = bits_modulo // 2
        self.primeP = self.Primo_probable(bitsPrimo, lista_primos)
        self.primeQ = self.Primo_probable(bitsPrimo, lista_primos)
        self.modulus = self.primeP * self.primeQ
        phi = (self.primeP - 1) * (self.primeQ - 1)
        self.privateExponent = pow(e, -1, phi)
        self.privateExponentModulusPhiP = self.privateExponent % (self.primeP - 1)
        self.privateExponentModulusPhiQ = self.privateExponent % (self.primeQ - 1)
        self.inverseQModulusP = pow(self.primeQ, -1,  self.primeP)     

    # constructora NO utilizada. Es idem al init por defecto, pero acepta un tercer 
    # parametro n. Este init lo hice para poder comprobar el voto, pero al final
    # he optado por usar el de las librerias como comentado en clase. Deberia de
    # poderse usar sin problemas, en comprobante_voto esta comentado el bloque
    # de codigo que usa este init
    def __init__(self, bits_modulo, e, n=None):
        """
        genera una clave RSA (de 2048 bits y exponente p´ublico 2**16+1 por defecto)
        """
        lista_primos = [i for i in range(256) if self.is_prime(i)]
        self.publicExponent = e 
        bitsPrimo = bits_modulo // 2
        self.primeP = self.Primo_probable(bitsPrimo, lista_primos)
        self.primeQ = self.Primo_probable(bitsPrimo, lista_primos)
        self.modulus = self.primeP * self.primeQ
        phi = (self.primeP - 1) * (self.primeQ - 1)
        self.privateExponent = pow(e, -1, phi)
        self.privateExponentModulusPhiP = self.privateExponent % (self.primeP - 1)
        self.privateExponentModulusPhiQ = self.privateExponent % (self.primeQ - 1)
        self.inverseQModulusP = pow(self.primeQ, -1,  self.primeP)     

        if n is not None:
            self.modulus = n



    def MGF (self, Z, l):
        T = bytes()
        i = 0
        while i < math.ceil(l / 31):  
            ii = i.to_bytes(4, 'big')
            T += hashlib.sha256(Z + ii).digest()
            i += 1
        return T[:l]


    # encoding operation, 9.1.1. con la diferencia de que M es entero
    def encoding_pss(self, M, emBits):
        emLen = (emBits + 7) // 8
        
        # max es necesario para que cuando M = 0, la firma no falle
        bytes_m = M.to_bytes(max(1, (M.bit_length() + 7) // 8), byteorder='big')
        #bytes_m = M.to_bytes((M.bit_length() + 7) // 8, 'big')

        # (1)
        if len(bytes_m) > (2**61) - 1:
            raise Exception("message too long")
        
        # (2)
        mHash = hashlib.sha256(bytes_m).digest()
        hLen = len(mHash)
        # sLen es el minimo de hLen y emLen - hLen - 2 para que las firmas con 
        # modulus menor a 1024 bits funcionen. Ya que si n.bit_length < 1024 ==> 
        # siempre se cumple la condicion emLen < (hLen + sLen + 2)
        # En el caso 512 bits: emLen = 64 < 66 = hLen + sLen + 2
        sLen = min(hLen, emLen - hLen - 2)

        # (3) 
        if emLen < (hLen + sLen + 2):
            raise Exception("encoding error")
        
        # (4) genero random salt
        salt = random.randbytes(sLen)
        # if sLen = 0, el salt es empty string
        if sLen == 0:
            salt = b''

        # (5)
        # M' es un coteto de length 8 + hLen + sLen
        M_prima = bytes(8) + mHash + salt

        # (6)
        H = hashlib.sha256(M_prima).digest()

        # (7) genera octet string PS de longitud emLen - sLen - hLen - 2
        PS = bytes(emLen - sLen - hLen - 2)

        # (8) DB es un octet string de longitud emLen - hLen - 1
        DB = PS + b'\x01' + salt 

        # (9)
        dbMask = self.MGF(H, emLen - hLen - 1)

        # (10) no se puede hacer XOR directamente en bytes, he de hacerlo con compresion de listas
        maskedDB = bytes([x ^ y for x, y in zip(DB, dbMask)])

        # (11) poner a cero los 8emLen - emBits mas significativos
        cero = 8*emLen - emBits
        if cero > 0:
            maskedDB = bytearray(maskedDB)
            maskedDB[0] &= (0xFF >> cero)
        maskedDB = bytes(maskedDB)

        # (12)
        EM = maskedDB + H + b'\xBC'  

        # (13) Output EM
        return EM




    def sign(self, message):
        """
        Entrada: un entero "message"
        Salida: un entero que es la firma de "message" hecha con la clave RSA usando el TCR
        """
        m = int.from_bytes(self.encoding_pss(message, self.modulus.bit_length() - 1), byteorder='big')
        if m < 0 or m > self.modulus - 1:
            raise Exception("message representative out of range")
        
        M_q = pow(m, self.privateExponentModulusPhiQ, self.primeQ)
        M_p = pow(m, self.privateExponentModulusPhiP, self.primeP)
        h = ((M_p - M_q) * self.inverseQModulusP) % self.primeP
        return ( (M_q + (self.primeQ * h)) % self.modulus )


    def sign_slow(self, message):
        """
        Entrada: un entero "message"
        Salida: un entero que es la firma de "message" hecha con la clave RSA sin usar el TCR
        """

        # valor maximo que puede tener es modulus.bit_length() - 1
        m = int.from_bytes(self.encoding_pss(message, self.modulus.bit_length() - 1), byteorder='big')
        if m < 0 or m > self.modulus - 1:
            raise Exception("message representative out of range")
        return pow(m, self.privateExponent, self.modulus)

    # funcion utilizada para testear si la firma resultante de slow y TCR era igual
    def sign_TCR_equals(self, message):
        m = int.from_bytes(self.encoding_pss(message, self.modulus.bit_length() - 1), byteorder='big')
        if m < 0 or m > self.modulus - 1:
            raise Exception("message representative out of range")
        
        M_q = pow(m, self.privateExponentModulusPhiQ, self.primeQ)
        M_p = pow(m, self.privateExponentModulusPhiP, self.primeP)
        h = ((M_p - M_q) * self.inverseQModulusP) % self.primeP
        
        return ( (M_q + (self.primeQ * h)) % self.modulus ) == pow(m, self.privateExponent, self.modulus)


    # mismo que 9.1.2. Verification Operation
    def EMSA_PSS_VERIFY (self, M, EM, emBits):
        emLen = math.ceil(emBits / 8)
        #sLen = 32 

        # (1) If the length of M is greater than the input 
        #     limitation for the hash function (2^61 - 1 
        #     octets for SHA-1), output "inconsistent" and 
        #     stop
        bytes_M = M.to_bytes(max(1, (M.bit_length() + 7) // 8), byteorder='big')
        if len(bytes_M) > 2**61 - 1:
            return "inconsistent"
        
        # (2) Let mHash = Hash(M), an octet string of length hLen
        mHash = hashlib.sha256(bytes_M).digest()
        hLen = len(mHash)
        # sLen es el minimo de hLen y emLen - hLen - 2 para que las firmas con 
        # modulus menor a 1024 bits funcionen. Ya que si n.bit_length < 1024 ==> 
        # siempre se cumple la condicion emLen < (hLen + sLen + 2)
        # En el caso 512 bits: emLen = 64 < 66 = hLen + sLen + 2
        sLen = min(hLen, emLen - hLen - 2)

        # (3) If emLen < hLen + sLen + 2, output "inconsistent" and stop
        if emLen < hLen + sLen + 2:
            return "inconsistent"
        
        # (4) If the rightmost octet of EM does not have hexadecimal 
        #     value 0xbc, output "inconsistent" and stop
        if EM[-1] != 0xbc:
            return "inconsistent"
        
        # (5) Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
        #     and let H be the next hLen octets
        maskedDB = EM[:emLen - hLen - 1]
        H = EM[emLen - hLen - 1: emLen - 1]

        # (6) Revisar bits sobrantes del primer octeto
        n_bits = 8 * emLen - emBits
        # Obtener el primer byte y aplicar máscara a los bits más significativos
        mask = (0xFF >> n_bits)  # bits menos significativos se conservan
        if (maskedDB[0] & (~mask & 0xFF)) != 0: # si algun bit que deberia no es 0, inconsistent
            return "inconsistent"

        # (7) Let dbMask = MGF(H, emLen - hLen - 1)
        dbMask = self.MGF(H, emLen - hLen - 1)

        # (8) Let DB = maskedDB \xor dbMask
        DB = bytes([x ^ y for x, y in zip(maskedDB, dbMask)])

        # (9) Set the leftmost 8emLen - emBits bits of the leftmost octet
        #     in DB to zero
        mask = 0xFF >> n_bits
        DB = bytearray(DB)
        DB[0] &= mask
        DB = bytes(DB)


        # (10)  If the emLen - hLen - sLen - 2 leftmost octets of DB are 
        #       not zero or if the octet at position 
        #       emLen - hLen - sLen - 1 (the leftmost position is 
        #      "position 1") does not have hexadecimal value 0x01, 
        #       output "inconsistent" and stop
        for x in DB[:emLen - hLen - sLen - 2]:
            if x != 0x00:
                return "inconsistent"
        if DB[emLen - hLen - sLen - 2] != 0x01:
            print(DB)
            print(DB[emLen - hLen - sLen + 188])

            return "inconsistent"
        
        # (11) Let salt be the last sLen octets of DB
        salt = DB[-sLen:]

        # (12) Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
        M_prima = bytes(8) + mHash + salt

        # (13) Let H' = Hash(M'), an octet string of length hLen
        H_prima = hashlib.sha256(M_prima).digest()

        # (14) If H = H', output "consistent"
        #      Otherwise, output "inconsistent"
        if H == H_prima:
            return "consistent"
        else:
            return "inconsistent"


    def verify(self, message, signature):
        """
        Entrada: dos enteros "message" y "signature"
        Salida: el booleano True si "signature" se corresponde con la firma de "message"
        hecha con la clave RSA;
        el booleano False en cualquier otro caso.
        """
        # (1) Length checking: If the length of the signature 
        # S is not k octets, output "invalid signature" and stop.
        k = (self.modulus.bit_length() + 7) // 8
        S_bytes = signature.to_bytes(k, byteorder='big')
        if len(S_bytes) != k: 
            raise Exception("invalid signature")
        
        ### RSA verification: ###
        
        # (2a) ya es implicito porque signature es entero
        # (2b) Apply the RSAVP1 verification primitive (Section 5.2.2) to
        #      the RSA public key (n, e) and the signature representative
        #      s to produce an integer message representative m:
        if signature < 0 or signature > self.modulus - 1:
            raise Exception("signature representative out of range")
        m = pow(signature, self.publicExponent, self.modulus)


        # (2c) convertir entero no negativo en octet string de longitud 
        emLen = (self.modulus.bit_length() - 1 + 7) // 8
        if m >= 256**emLen:
            raise Exception("invalid signature")        # integer muy grande
        EM = m.to_bytes(emLen, byteorder='big')


        # (3) Result = EMSA-PSS verification
        Result = self.EMSA_PSS_VERIFY (message, EM, self.modulus.bit_length() - 1)

        # (4) If Result = "consistent", output "valid signature".
        #     Otherwise, output "invalid signature".
        if Result == "consistent":
            return True
        else:
            return False
            


    def __repr__(self):
        return str(self.__dict__)
    
    def from_dictionary(self, RSAKey):
        """
            Importa una clave RSA:
        """
        RSAKey = {
            "publicExponent": 65537,
            "modulus": 570131475606908079645289541584935910730810198868796008957155625353952799,
            "privateExponent": 4753342970712949550913014106871064919409107720248258835378333364,
            "primeP": 6984543319619713760180514011748821810865467260539703382978371694181772714,
            "primeQ": 8162759532257435135158099414290415000169780797669900784827582678722199767,
            "privateExponentModulusPhiP": 45804459669184686161831989824214201536412548238511972,
            "privateExponentModulusPhiQ": 23195305059619789511581135143862306567002125180433428,
            "inverseQModulusP": 567233782337109666186598736353187660521719314613992812595580843
        }
        self.publicExponent = RSAKey["publicExponent"]
        self.privateExponent = RSAKey["privateExponent"]
        self.modulus = RSAKey["modulus"]
        self.primeP = RSAKey["primeP"]
        self.primeQ = RSAKey["primeQ"]
        self.privateExponentModulusPhiP = RSAKey["privateExponentModulusPhiP"]
        self.privateExponentModulusPhiQ = RSAKey["privateExponentModulusPhiQ"]
        self.inverseQModulusP = RSAKey["inverseQModulusP"]


