from RSA_Lab_25 import rsa_key
import random
import time

mensajes = [0] * 1024
size_claves = [0] * 1024
tiempo_firma_sin_TCR = [0] * 1024
tiempo_firma_con_TCR = [0] * 1024
tiempo_verify_sin_TCR =  [0] * 1024
tiempo_verify_con_TCR =  [0] * 1024
proporcion_TCR_slow =  [0.0] * 1024
for i in range(len(mensajes)):
    mensajes[i] = random.randint(1, 10**20)
    #  claves de 512, 1024, 2048, 4096 y 8192 bits
    #  que aumentan cada 200 claves
    size_claves[i] = 2**(9 + (min(i, 800) // 200))

rsax = rsa_key(512, 2**16 + 1)
k = 512
for i, m in enumerate(mensajes):
    
    k_new = 2**(9 + (min(i, 800) // 200))
    if k != k_new:                  # en esta condicion
        #print (f"cambio de clave: {k} --> {k_new}")
        #print (f"encaja con el tamaño de la clave real? {k_new} == {size_claves[i]}")
        #print (f"y la anterior es {k_new} == {size_claves[i-1]}")
        k = k_new
        rsax = rsa_key(k, 2**16 + 1)

    init = time.perf_counter()
    fm = rsax.sign_slow(m)
    end = time.perf_counter()
    tiempo_firma_sin_TCR[i] = end - init
    slow_time = end - init


    init = time.perf_counter()
    fm_TCR = rsax.sign(m)
    end = time.perf_counter()
    tiempo_firma_con_TCR[i] = end - init
    TCR_time = end - init    

    
    if not rsax.sign_TCR_equals(m):
        raise RuntimeError("ERROR: firmas NO identicas")

    init = time.perf_counter()
    isVerified = rsax.verify(m, fm)
    end = time.perf_counter()
    tiempo_verify_sin_TCR[i] = end - init

    if not isVerified:
        raise RuntimeError("ERROR: firma sin TCR NO correcta")

    init = time.perf_counter()
    isVerified = rsax.verify(m, fm_TCR)
    end = time.perf_counter()
    tiempo_verify_con_TCR[i] = end - init

    if not isVerified:
        raise RuntimeError("ERROR: firma con TCR NO correcta")
    
    proporcion_TCR_slow[i] = slow_time / TCR_time

header1 = "Tamaño Clave"
header2 = "Firma sin TCR"
header3 = "Firma con TCR"
header4 = "Verify firma sin TCR"
header5 = "Verify firma con TCR"
header6 = "sin TCR / con TCR"

media512_slow = sum(tiempo_firma_sin_TCR[:200])/200
media1024_slow = sum(tiempo_firma_sin_TCR[200:400])/200
media2048_slow = sum(tiempo_firma_sin_TCR[400:600])/200
media4096_slow = sum(tiempo_firma_sin_TCR[600:800])/200
media8192_slow = sum(tiempo_firma_sin_TCR[800:1024])/(224)

media512_TCR = sum(tiempo_verify_con_TCR[:200])/200
media1024_TCR = sum(tiempo_verify_con_TCR[200:400])/200
media2048_TCR = sum(tiempo_verify_con_TCR[400:600])/200
media4096_TCR = sum(tiempo_verify_con_TCR[600:800])/200
media8192_TCR = sum(tiempo_verify_con_TCR[800:1024])/(224)

media_proporcion_TCR_slow = sum(proporcion_TCR_slow)/1024

with open("tabla_tiempos.txt", "w") as f:
    # media de todos los tiempos sin TCR clasificado por el size de la clave
    f.write(f"Sin TCR: media512 = {media512_slow}; media1024 = {media1024_slow}; media2048 = {media2048_slow}; media4096 = {media4096_slow}; media8192 = {media8192_slow};\n")
    # media de todos los tiempos con TCR clasificado por el size de la clave
    f.write(f"Con TCR: media512 = {media512_TCR}; media1024 = {media1024_TCR}; media2048 = {media2048_TCR}; media4096 = {media4096_TCR}; media8192 = {media8192_TCR};\n")
    # Sin TCR: relacion de la media del tiempo de firma con claves de X bits con 2*X bits
    f.write(f"SinTCR-1024/SinTCR-512 = {media1024_slow/media512_slow}; SinTCR-2048/SinTCR-1024 = {media2048_slow/media1024_slow}; SinTCR-4096/SinTCR-2048 = {media4096_slow/media2048_slow}; SinTCR-8192/SinTCR-4096 = {media8192_slow/media4096_slow};\n")
    # Con TCR: relacion de la media del tiempo de firma con claves de X bits con 2*X bits
    f.write(f"TCR-1024/TCR-512 = {media1024_TCR/media512_TCR}; TCR-2048/TCR-1024 = {media2048_TCR/media1024_TCR}; TCR-4096/TCR-2048 = {media4096_TCR/media2048_TCR}; TCR-8192/TCR-4096 = {media8192_TCR/media4096_TCR};\n")
    # relacion de las medias del tiempo de las 1024 firmas (con TCR / sin TCR)
    f.write(f"media de la relacion del tiempo de las 1024 firmas (con TCR / sin TCR): {media_proporcion_TCR_slow}\n")
    f.write(f"{header1:<25}{header2:<25}{header3:<25}{header4:<25}{header5:<25}{header6:<25}\n")
    f.write("-" * 120 + "\n")
    
    for a, b, c, d, e, g in zip(size_claves, tiempo_firma_sin_TCR, tiempo_firma_con_TCR, tiempo_verify_sin_TCR, tiempo_verify_con_TCR, proporcion_TCR_slow):
        f.write(f"{str(a):<25}{str(b):<25}{str(c):<25}{str(d):<25}{str(e):<25}{str(g):<25}\n")