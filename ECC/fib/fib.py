import os

# EL PAQUETE CLIENT HELLO DE WWW.FIB.UPC.EDU ES EL NUMERO 301
# EL PAQUETE SERVER HELLO DE WWW.FIB.UPC.EDU ES EL NUMERO 307
# EL PAQUETE CERTIFICATE, SERVER DE WWW.FIB.UPC.EDU ES EL NUMERO 319
# EL FICHERO PARA DESCIFRAR LOS PAQUETES ES TLS_keys_descifrar_fib.txt

# contar numero de certificados revocados
print("numero de certificados revocados:")
os.system("openssl crl -in HARICA-GEANT-TLS-R1.crl -text -noout | grep 'Revocation Date' | wc -l")

# contar numero de certificados revocados por Key Compromise
print("numero de certificados revocados por Key Compromise:")
os.system("openssl crl -in HARICA-GEANT-TLS-R1.crl -text -noout | grep 'Key Compromise' | wc -l")

# ver el estado del certificado de fib.upc.edu
os.system("openssl ocsp -issuer certificado_CA.pem -cert certificado_FIB.pem -url http://ocsp-tls.harica.gr -resp_text -respout status.der")