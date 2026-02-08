import math
from Crypto.PublicKey import RSA
import subprocess


with open("pol.garcia.vernet_pubkeyRSA_ptE.pem", "rb") as f:
    pem = RSA.import_key(f.read())

n = pem.n    
e = pem.e      

print(f"clave publica: {pem}")
print("n =", n)
print("e =", e)
print(f"numero bits de n = {n.bit_length()}")

p = q = 0
K = EPS = 0

for k in range(n.bit_length()):
    for epsilon in range(0, 100000):
        aux = (e + epsilon) * (2**k)
        x = math.isqrt(n + (aux // 2)**2)
        p = x + (aux // 2)
        q = x - (aux // 2)
        if p * q == n and e == int(((p - q) // (2**k))) - epsilon:
            print(f"ENCONTRADO con k = {k} y epsilon = {epsilon}")
            K = k 
            EPS = epsilon
            break
    if p * q == n and e == int(((p - q) // (2**k))) - epsilon:
        break

# con p q calculados, calculamos el exponente privado d
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# verificamos que efectivamente hemos encontrado d:
print(f"p * q == n                  ?    {p*q == n}")
print(f"mcd(e, phi(n)) == 1         ?    {math.gcd(e, phi) == 1}")
print(f"d * e = 1 mod mcm(p-1, q-1) ?    {(d * e) % ( math.lcm(p - 1, q - 1)) == 1 }")
print(f"mcd(p-1, e) == 1            ?    {math.gcd(p-1, e) == 1}")
print(f"mcd(q-1, e) == 1            ?    {math.gcd(q-1, e) == 1}")
print(f"e == (p-q)/2^k - eps        ?    {e == ((p - q) // (2**K)) - EPS}")
print(f"k tq. (p-q)/2^k impar       ?    {((p - q) // (2**k) % 2 == 1)}")

# prueba con un mensaje arbitrario
m = 4258718947105987580741057014571857841057915718057094675867210
c = pow(m, e, n)
m2 = pow(c, d, n)
print(f"cifrado == descifrado       ?    {m == m2}")


key = RSA.construct((n, e, d, p, q))
clave_privada_d = key.export_key()
# con las siguientes lineas se generan los ficheros pedidos en la entrega: 
#                                                                           1. clave_privada_d.pem
#                                                                           2. pol.garcia.vernet_RSA_ptE
#                                                                           3. pol.garcia.vernet_AES_ptE
with open("clave_privada_d.pem", "wb") as f:
    f.write(clave_privada_d)

subprocess.run("openssl pkeyutl -decrypt -inkey ./clave_privada_d.pem -in ./pol.garcia.vernet_RSA_ptE.enc -out ./pol.garcia.vernet_RSA_ptE", check=True)
subprocess.run("openssl enc -d -aes-128-cbc -pbkdf2 -kfile ./pol.garcia.vernet_RSA_ptE -in ./pol.garcia.vernet_AES_ptE.enc -out ./pol.garcia.vernet_AES_ptE", check=True)
