import math
import hashlib
import copy

class G_F:

    # calcula la tablaEXP dado un polinomio g
    def calcularTabla(self, g):
        tamanno_tabla = 255
        EXP_Box = [0] * tamanno_tabla
        i = 0

        resultado_producto = 0x01
        EXP_Box[i] = resultado_producto
        i += 1
        resultado_producto = self.producto_sin_tabla(resultado_producto, g)

        # genera la tabla donde cada elemento es g**i
        while (resultado_producto != 0x01) and (i < tamanno_tabla):   
            EXP_Box[i] = resultado_producto
            i += 1
            resultado_producto = self.producto_sin_tabla(resultado_producto, g)

        if i != tamanno_tabla:
            raise Exception("Tabla Incorrecta, 1 generado antes de terminar")
        
        return EXP_Box

    def generarTablaEXP(self):
        # empieza en g = 0x02 e intenta generar la tablaEXP
        g = 0x02
        EXP_Box = 255*[0]
        while (True):
            try:
                EXP_Box = self.calcularTabla(g)
                break
            # si recibe una excepcion, entonces significa que el valor de g no es suficiente
            # por ejemplo: si con 2 obtenemos un 0x01 antes de terminar la tabla, probamos 
            # g = 3
            except:
                g = g + 1
        self.g = g
        return EXP_Box
            
    def generarTablaLOG(self):
        tamanno_tabla = 256
        LOG_box = tamanno_tabla*[0]

        for i in range(tamanno_tabla - 1):
            LOG_box[self.Tabla_EXP[i]] = i

        # no existe un elemento de la tabla tq. Tabla_EXP[i] = 0x00
        LOG_box[0] = None 

        return LOG_box




    """
    Genera un cuerpo finito usando como polinomio irreducible el dado
    representado como un entero. Por defecto toma el polinomio del AES.
    Los elementos del cuerpo los representaremos por enteros 0<= n <= 255.
    """
    def __init__(self, Polinomio_Irreducible):
        """
        Entrada: un entero que representa el polinomio para construir el cuerpo
        Tabla_EXP y Tabla_LOG dos tablas, la primera tal que en la posici´on
        i-´esima tenga valor a=g**i y la segunda tal que en la posici´on a-´esima
        tenga el valor i tal que a=g**i. (g generador del cuerpo finito
        representado por el menor entero entre 0 y 255.)
        """
        self.Polinomio_Irreducible = Polinomio_Irreducible
        # genera tabla (lista) donde cada elemento es g**i
        # self.g es calculado en esta misma funcion
        self.Tabla_EXP = self.generarTablaEXP()

        # genera tablaLOG
        self.Tabla_LOG = self.generarTablaLOG()
        # self.g


    def xTimes(self, n):
        """
        Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de ’n’ y 0x02 (el polinomio X).
        """
        n = n << 1 
        if n & 0x100:
            n = n ^ self.Polinomio_Irreducible
        return n
        
    def producto(self, a, b):
        """
        Entrada: dos elementos del cuerpo representados por enteros entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de la entrada.
        Atenci´on: Se valorar´a la eficiencia. No es lo mismo calcularlo
        usando la definici´on en t´erminos de polinomios o calcular
        usando las tablas Tabla_EXP y Tabla_LOG.
        """
        if a == 0 or b == 0:
            return 0
        # ====================== CON TABLA ======================
        result = self.Tabla_EXP[(self.Tabla_LOG[a] + self.Tabla_LOG[b])%255]
        return result


    def producto_sin_tabla(self, a, b):
        """
        Entrada: dos elementos del cuerpo representados por enteros entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de la entrada.
        Atenci´on: Se valorar´a la eficiencia. No es lo mismo calcularlo
        usando la definici´on en t´erminos de polinomios o calcular
        usando las tablas Tabla_EXP y Tabla_LOG.
        """

        # ====================== SIN TABLA ====================== 
        # ========== SOLO UTILIZADO PARA CREAR LA TABLA =========
        result = 0
        for i in range(0, 8):
            # voy leyendo bits y sumo a, ax, axx, axxx
            if b & 0x01:
                result = result ^ a
            b = b >> 1
            a = self.xTimes(a)
        return result

    def inverso(self, n):
        """
        Entrada: un elementos del cuerpo representado por un entero entre 0 y 255
        Salida: 0 si la entrada es 0,
        el inverso multiplicativo de n representado por un entero entre
        1 y 255 si n <> 0.
        Atenci´on: Se valorar´a la eficiencia.
        """
        if n == 0x00:
            # Salida: 0 si la entrada es 0,
            return 0
        else:
            return self.Tabla_EXP[(255 - self.Tabla_LOG[n])%255]
        

class AES:
    """
    Documento de referencia:
    Federal Information Processing Standards Publication (FIPS) 197: Advanced Encryption
    Standard (AES) https://doi.org/10.6028/NIST.FIPS.197-upd1
    El nombre de los m´etodos, tablas, etc son los mismos (salvo capitalizaci´on)
    que los empleados en el FIPS 197
    """

    # desplaza hacia la izquierda el byte x un numero shift de posiciones
    def rotacionLeft8(self, x, shift):
        return ((x << shift) | (x >> (8 - shift))) & 0xFF

    def inicializaSBox(self):
        S_Box = [0] * 256

        for i in range(256):
            # 1 - toma el inverso en GF(2^8)
            inverso = self.gf.inverso(i)
            # 2 - aplica la transformacion afin sobre GF(2):
            # el ^ 0x63 al final es para que S_Box[0] = 0x63
            x = inverso ^ self.rotacionLeft8(inverso, 1) ^ self.rotacionLeft8(inverso, 2) ^  self.rotacionLeft8(inverso, 3) ^ self.rotacionLeft8(inverso, 4) ^ 0x63
            S_Box[i] = x 
        return S_Box
    
    def inicializaInvSBox(self, InvSBox):

        for i in range(len(InvSBox)):
            InvSBox[self.SBox[i]] = i
        return InvSBox

    # construye la matriz Rcon equivalente a la tabla 5, pag. 17
    def roundConstantsTable(self, Polinomio_Irreducible):
        rcon = [0]*40

        i = 0
        while i < len(rcon):
            if i == 0:
                rcon[i] = 1
            elif i > 0 and rcon[i - 4] < 0x80:
                rcon[i] = 2*rcon[i - 4]
            elif i > 0 and rcon[i - 4] >= 0x80:
                rcon[i] = (((2*rcon[i - 4]) ^ Polinomio_Irreducible))
            i = i + 4

        return rcon
            
    def inversaMatriz_GF(self, MixMatrix):
        n = 4
        matriz_identidad = [[0x01, 0x00, 0x00, 0x00], 
                            [0x00, 0x01, 0x00, 0x00], 
                            [0x00, 0x00, 0x01, 0x00], 
                            [0x00, 0x00, 0x00, 0x01]]
        matriz_aumentada = [[0 for _ in range(2*n)] for _ in range(n)]

        for i in range(n):
            for j in range(n):
                matriz_aumentada[i][j] = MixMatrix[i][j]
                matriz_aumentada[i][j + n] = matriz_identidad[i][j]

        # comienza Gauss-Jordan en el cuerpo G_F
        for i in range(n):
            if matriz_aumentada[i][i] == 0:
                for k in range(i + 1, n):
                    # intercambia filas 'i' y 'k'
                    if matriz_aumentada[k][i] != 0:
                        aux_fila = matriz_aumentada[i]
                        matriz_aumentada[i] = matriz_aumentada[k]
                        matriz_aumentada[k] = aux_fila
                        break
                    if matriz_aumentada[i][j] == 0:
                        raise Exception (f"Error: matriz no invertible")
                
            pivote = matriz_aumentada[i][i]
            for j in range(2*n):
                # matriz_aumentada[i][j] = matriz_aumentada[i][j] / pivote
                matriz_aumentada[i][j] = self.gf.producto(matriz_aumentada[i][j], self.gf.inverso(pivote))
            
            for k in range(n):
                if k != i:
                    factor = matriz_aumentada[k][i]
                    for j in range(2*n):
                        matriz_aumentada[k][j] = matriz_aumentada[k][j] ^ self.gf.producto(factor, matriz_aumentada[i][j])

        inversa_MixMatrix = []

        for i in range(n):
            fila_inversa = []
            for j in range(n):
                fila_inversa.append(matriz_aumentada[i][j + n])
            inversa_MixMatrix.append(fila_inversa)

        return inversa_MixMatrix


    def __init__(self, key, Polinomio_Irreducible):
        """
        Entrada:
        key: bytearray de 16 24 o 32 bytes
        Polinomio_Irreducible: Entero que representa el polinomio para construir
        el cuerpo
        SBox: equivalente a la tabla 4, p´ag. 14
        InvSBOX: equivalente a la tabla 6, p´ag. 23
        Rcon: equivalente a la tabla 5, p´ag. 17
        InvMixMatrix : equivalente a la matriz usada en 5.3.3, p´ag. 24
        """

        self.Polinomio_Irreducible = Polinomio_Irreducible
        # garlois field que utilizare en mixColumns e InvMixColumns y en inicializaSBox
        self.gf = G_F(Polinomio_Irreducible)
        # dada una key en formato string, conviertelo a formato lista donde cada elemento es un byte
        self.key = list(key)
        self.SBox = self.inicializaSBox()
        self.InvSBox = self.inicializaInvSBox(256*[0])
        self.Rcon = self.roundConstantsTable(Polinomio_Irreducible)
        # MixMatrix se deduce del polinomio c(x) en la diapositiva 23/53
        # el motivo por el que se coge este polinomio en concreto es
        # arbitrario. se coloca, y se hacen shifts
        # la MixMatriz se guarda aqui para ahorrar el coste de declararla
        # en mixColumns. Idem a self.InvMixMatrix
        self.MixMatriz = [[0x02, 0x03, 0x01, 0x01], 
                          [0x01, 0x02, 0x03, 0x01], 
                          [0x01, 0x01, 0x02, 0x03], 
                          [0x03, 0x01, 0x01, 0x02]]
        # obtengo InvMixMatriz calculando la inversa de la matriz MixMatriz en el cuerpo G_F
        self.InvMixMatrix = self.inversaMatriz_GF(self.MixMatriz)

    def SubBytes(self, State):
        """
        5.1.1 SUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        """
        n = math.sqrt(len(self.SBox))

        # por cada elemento, lo sustituye por el determinado por la SBox
        for j in range(len(State[0])):
            for i in range(len(State)):
                valor = State[j][i]
                fila = (valor & 0xf0) >> 4
                columna = valor & 0x0f
                State[j][i] = self.SBox[int((fila * n) + columna)]


    def InvSubBytes(self, State):
        """
        5.3.2 INVSUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        """        
        n = math.sqrt(len(self.SBox))

        for j in range(len(State[0])):
            for i in range(len(State)):
                valor = State[j][i]
                fila = (valor & 0xf0) >> 4
                columna = valor & 0x0f
                State[j][i] = self.InvSBox[int((fila * n) + columna)]

    def ShiftRows(self, State):
        """
        5.1.2 SHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        """
        for i in range(1, len(State)):
            # el segundo bucle sirve para indicar que la fila 0 se desplaza 0 veces,
            # la fila 1 se desplaza 1 veces, y asi sucesivamente
            for _ in range(i):
                valorAux = State[i][0]
                for j in range(len(State[0])):
                    if (j + 1) < len(State[0]):
                        State[i][j] = State[i][j + 1]
                    else:
                        State[i][j] = valorAux


    def InvShiftRows(self, State):
        """
        5.3.1 INVSHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        """
        # idem a ShiftRows, pero en sentido contrario
        for i in range(1, len(State)):
            for _ in range(i):
                valorAux = State[i][len(State[0]) - 1]
                j = len(State[0]) - 1
                while j >= 0:
                    if (j - 1) >= 0:
                        State[i][j] = State[i][j - 1]
                    else:
                        State[i][j] = valorAux    
                    j = j - 1  

    def MixColumns(self, State):
        """
        5.1.3 MIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        """
        # matriz vacia del mismo tamanno que State
        resultado_matrix = [[0 for _ in fila] for fila in State]

        for j in range(len(State[0])):
            for i in range(len(State)):
                for k in range(len(State[0])):
                    resultado_matrix[i][j] ^= self.gf.producto(self.MixMatriz[i][k], State[k][j])

        # copia la matriz, no sirve hacer State = resultado_matrix porque 
        # se pasa por referencia, pero el nombre es local
        for i in range(len(State)):
            for j in range(len(State[0])):
                State[i][j] = resultado_matrix[i][j]
                


    def InvMixColumns(self, State):
        """
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        """
        # InvMixColumns is idem a MixColumns, pero con otras diapositivas
        # MixMatrix se deduce del polinomio c(x) en la diapositiva 23/53
        # el motivo por el que se coge este polinomio en concreto es
        # arbitrario. se coloca, y se hacen shifts

        resultado_matrix = [[0 for _ in fila] for fila in State]

        for j in range(len(State[0])):
            for i in range(len(State)):
                for k in range(len(State[0])):
                    resultado_matrix[i][j] ^= self.gf.producto(self.InvMixMatrix[i][k], State[k][j])
    
        # copia la matriz, no sirve hacer State = resultado_matrix porque 
        # se pasa por referencia, pero el nombre es local
        for i in range(len(State)):
            for j in range(len(State[0])):
                State[i][j] = resultado_matrix[i][j]
    
    def AddRoundKey(self, State, roundKey):
        """
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        """
        for i in range(len(State)):
            for j in range(len(State[0])):
                    # los indices de roundKey estan invertidos porque
                    # el formato de la ExpandedKEY es de (4 columnas) x (n filas)
                    # por eso mismo, la submatrix (roundKey) nos da
                    # una traspuesta de la matriz que realmente necesitamos
                    State[i][j] = State[i][j] ^ roundKey[j][i]
    
    # rota una word igual que en MixColumns una posicion
    def rotWord(self, word):
        valorAux = word[0]
        for i in range(len(word)):
            if (i + 1) < len(word):
                word[i] = word[i + 1]
            else:
                word[i] = valorAux
        return word

    # sustituye una word por sus valores en la SBox, similar a SubBytes
    def SubBytesWord(self, word):
        n = math.sqrt(len(self.SBox))
        for i in range(len(word)):
            valor = word[i]
            fila = (valor & 0xf0) >> 4
            columna = valor & 0x0f
            word[i] = self.SBox[int((fila * n) + columna)]


    def KeyExpansion(self, key):
        # KeyExpansion algorithm, identico al pseudocodigo de 
        # Advanced Encryption Standard, con algunas adaptaciones 
        # en los indices para que las estructuras y los tipos 
        # utilizados (como Rcon y la key) sean equivalentes
        i = 0
        Nk = round(len(key) / 4)
        Nr = Nk + 6
        expandedKey = [[0 for _ in range(4)] for _ in range((Nr + 1) * 4)]
        while i <= Nk - 1:
            expandedKey[i] = key[4 * i : 4 * i + 4]
            i = i + 1
        while i <= 4 * Nr + 3:
            temp = [0] * 4
            for ind in range(len(expandedKey[i - 1])):
                temp[ind] = expandedKey[i - 1][ind]

            if i % Nk == 0:
                self.rotWord(temp)
                self.SubBytesWord(temp)
                for k in range(len(temp)):
                    temp[k] = temp[k] ^ self.Rcon[round(4 * (i - Nk) / Nk) + k]
            elif Nk > 6 and i % Nk == 4:
                self.SubBytesWord(temp)
            # end if
            for k in range(len(expandedKey[i])):
                expandedKey[i][k] = expandedKey[i - Nk][k] ^ temp[k]
            i = i + 1
        return expandedKey




    def Cipher(self, State, Nr, Expanded_KEY):
        """
        5.1 Cipher(), Algorithm 1 p´ag. 12
        FIPS 197: Advanced Encryption Standard (AES)
        """
        sub_Expanded_KEY = Expanded_KEY[0:4]
        self.AddRoundKey(State, sub_Expanded_KEY)
        for r in range(1, Nr):
            self.SubBytes(State)
            self.ShiftRows(State)
            self.MixColumns(State)
            sub_Expanded_KEY = Expanded_KEY[4 * r :   4 * r + 4]
            self.AddRoundKey(State, sub_Expanded_KEY)
        self.SubBytes(State)
        self.ShiftRows(State)
        self.AddRoundKey(State, Expanded_KEY[4 * Nr :   4 * Nr + 4])
        return State


    def InvCipher(self, State, Nr, Expanded_KEY):
        """
        5. InvCipher()
        Algorithm 3 p´ag. 20 o Algorithm 4 p´ag. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        """
        sub_Expanded_KEY = Expanded_KEY[4 * Nr : 4 * Nr + 4]
        self.AddRoundKey(State, sub_Expanded_KEY)
        for r in range(Nr - 1, 0, -1):
            self.InvShiftRows(State)
            self.InvSubBytes(State)
            sub_Expanded_KEY = Expanded_KEY[4 * r :   4 * r + 4]
            self.AddRoundKey(State, sub_Expanded_KEY)
            self.InvMixColumns(State)
        self.InvShiftRows(State)
        self.InvSubBytes(State)
        self.AddRoundKey(State, Expanded_KEY[0:4])
        return State

    def obtener_IV(self):
        concatenacion = "IV".encode() + bytes(self.key)
        concatenacion_bytes = hashlib.sha256(concatenacion).hexdigest()[0:32]
        pares = [int(concatenacion_bytes[i:i+2], 16) for i in range(0, len(concatenacion_bytes), 2)]
        resultado = [[0] * 4 for _ in range(4)]
        for j in range(4):
            for i in range(4):
                # indices para acceder a pares invertidos, asi leemos por columnas!!
                resultado[i][j] = pares[j * 4 + i]
        return resultado


    # anade padding al final del fichero segun PKCS7
    def anade_padding(self, fichero_en_bytes, k):        
        lth = len(fichero_en_bytes)
        i = lth % k 
        # el valor del padding = bytes restantes para un bloque entero
        valor_padding = k - i
        while i < k:
            fichero_en_bytes = fichero_en_bytes + valor_padding.to_bytes()
            i += 1
        return fichero_en_bytes
    
    # dado una estructura unidimensional (data), retorna
    # el contenido en formato de bloques donde cada elemento 
    # es una matriz (bloque) de tamano k. Por ejemplo:
    # data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    # k = 2
    # data_por_bloques = [[[1, 3], [2, 4]], [[5, 7], [6, 8]], [[9, 11], [10, 12]]]
    def divide_por_bloques(self, data, k):
        data_por_bloques = []
        lth_padding = len(data)
        sqrt_k = int(math.sqrt(k))
        for b in range(int(lth_padding / k)):
            bloque = [[_ for _ in range(sqrt_k)] for row in range(sqrt_k)]
            for i in range(sqrt_k):
                for j in range(sqrt_k):
                    # indices invertidos ya que leemos por columnas!!
                    bloque[j][i] = int(data[(b*k) + i * sqrt_k + j])
            data_por_bloques.append(bloque)

        return data_por_bloques
    
    # dado una estructura por bloques (data_por_bloques), retorna
    # el contenido en bytearrat si sus bloques son de tamano k
    # Por ejemplo:
    # data_por_bloques = [[[1, 2], [3, 4]], [[5, 6], [7, 8]], [[9, 10], [11, 12]]]
    # k = 2
    # data = [1, 3, 2, 4, 5, 7, 6, 8, 9, 11, 10, 12] (en bytearrays)
    def bloques_a_bytes(self, data_por_bloques, k):
        byte_array = bytearray()
        sqrt_k = int(math.sqrt(k))
        for b in range(len(data_por_bloques)):
            for i in range(sqrt_k):
                for j in range(sqrt_k):
                    # indices invertidos ya que leemos por columnas!!
                    byte_array.append(data_por_bloques[b][j][i])
        return byte_array
    
    # XOR entre dos bloques a[i][j] ^ b[i][j]
    def XOR_bloques(self, IV_asociado, bloque):
        k = len(bloque)
        Input_block = [[0 for _ in range(k)] for row in range(k)]
        for i in range(k):
            for j in range(k):
                Input_block[i][j] = IV_asociado[i][j] ^ bloque[i][j]
        return Input_block


    def encrypt_file(self, fichero):
        """
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor
        de la clase.
        Para cifrar se usar´a el modo CBC, con IV correspondiente a los 16
        primeros bytes obtenidos al aplicar el sha256 a la concatenaci´on
        de "IV" y la clave usada para cifrar. Por ejemplo:
        Key 0x0aba289662caa5caaa0d073bd0b575f4
        IV asociado 0xeb53bf26511a8c0b67657ccfec7a25ee
        Key 0x46abd80bdcf88518b2bec4b7f9dee187b8c90450696d2b995f26cdf2fe058610
        IV asociado 0x4fe68dfd67d8d269db4ad2ebac646986
        El padding usado ser´a PKCS7.
        El nombre de fichero cifrado ser´a el obtenido al a~nadir el sufijo .enc
        al nombre del fichero a cifrar: NombreFichero --> NombreFichero.enc
        """
        data = open(fichero, "rb").read()
        IV_asociado = self.obtener_IV()
        # size bloque Input en bytes
        k = 16

        # annadiendo padding PKCS7
        data_padding = self.anade_padding(data, k)
        data_por_bloques = self.divide_por_bloques(data_padding, k)
        # numero de rondas segun la longitud de la key
        Nr = 0
        if len(self.key) == 16:
            Nr = 10
        elif len(self.key) == 24:
            Nr = 12
        elif len(self.key) == 32:
            Nr = 14

        # calcula la ExpandedKey
        expKEY = self.KeyExpansion(self.key)

        output_por_bloques = []

        # -------------------------- comienza el modo de operacion CBC --------------------------

        # se hace XOR entre IV y primer Plain Text
        input = self.XOR_bloques(IV_asociado, data_por_bloques[0])
        # se cifra y se concatena en el output_por_bloques (que sera el resultado)
        output_b = self.Cipher(input, Nr, expKEY)
        output_por_bloques.append(output_b)

        # repite por cada bloque y haciendo XOR con el anterior bloque cifrado
        for b in range(1, len(data_por_bloques)):
            input_b = self.XOR_bloques(output_b, data_por_bloques[b])
            output_b = self.Cipher(input_b, Nr, expKEY)
            output_por_bloques.append(output_b)
        # ---------------------------------------------------------------------------------------

        # convierte los bloques cifrados a bytes para escribir en fichero
        cipher_data = self.bloques_a_bytes(output_por_bloques, k)
        out_file = open(fichero + ".enc", "wb") 
        out_file.write(cipher_data)
        
    def quitar_padding(self, data, k):        
        padding_len = data[len(data) - 1] 
        # comprobaciones de que el padding es correcto
        if padding_len > k or padding_len < 1:
            raise Exception(f"Padding no es correcto: valor del padding = {hex(padding_len)}")
        if bytes([padding_len] * padding_len) != data[-padding_len:]:
            raise Exception(f"Padding no es correcto, algun byte del padding no es valido. Padding = {data[-padding_len:]}")
        return data[:-padding_len]

    def decrypt_file(self, fichero):
        """
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor
        de la clase.
        Para descifrar se usar´a el modo CBC, con el IV usado para cifrar.
        El nombre de fichero descifrado ser´a el obtenido al a~nadir el sufijo .dec
        al nombre del fichero a descifrar: NombreFichero --> NombreFichero.dec
        """
        data = open(fichero, "rb").read()

        # genera el IV_asociado
        IV_asociado = self.obtener_IV()
        # size bloque Input en bytes
        k = 16
        # input length
        lth = len(data) * k

        data_por_bloques = self.divide_por_bloques(data, k)

        # numero de rondas segun la longitud de la key
        Nr = 0
        if len(self.key) == 16:
            Nr = 10
        elif len(self.key) == 24:
            Nr = 12
        elif len(self.key) == 32:
            Nr = 14
        
        # calcula la ExpandedKey
        expKEY = self.KeyExpansion(self.key)


        plain_text = [] * int(lth / k)    

        # -------------------------- comienza el modo de operacion CBC --------------------------
        # se descifra el primer bloque
        output_b = self.InvCipher(copy.deepcopy(data_por_bloques[0]), Nr, expKEY)
        # se hace XOR con el descifrado y el IV para obtener el resultado
        plain_text_block = self.XOR_bloques(IV_asociado, output_b)
        # concatena el resultado al array plain_text, que contiene todos los
        # bloques descifrado
        plain_text.append(plain_text_block)


        # repite para cada bloque y haciendo XOR con el anterior bloque
        for b in range(1, len(data_por_bloques)):
            output_b = self.InvCipher(copy.deepcopy(data_por_bloques[b]), Nr, expKEY)
            plain_text_block = self.XOR_bloques(data_por_bloques[b - 1], output_b)
            plain_text.append(plain_text_block)
        # --------------------------------------------------------------------------------------

        # decipher_text = plain_text a bytes
        decipher_text = self.bloques_a_bytes(plain_text, k)

        # elimina el padding
        decipher_text = self.quitar_padding(bytes(decipher_text), k)

        out_file = open(fichero + ".dec", "wb") 
        out_file.write(decipher_text)

