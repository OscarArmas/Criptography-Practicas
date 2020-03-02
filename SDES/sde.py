class SDES:
    def __init__(self):

        self.Array = {0:['01','00','11','10'],
                1:['11','10','01','00'],
                2:['00','10','01','11'],
                3:['11','01','11','10']}
        self.Array_2 = {0:['00','01','10','11'],
                1:['10','00','01','11'],
                2:['11','00','01','00'],
                3:['10','01','00','11']}


    def find_Sbox(self,x,y,Sbox= True):
        x= int(x,2)
        y = int(y,2)
        return  Sbox[x][y]
        
    def permutate_(self,cipher, plaintext):
        ciphertext = ""
        for offset in range(0, len(plaintext), len(cipher)):
            #print(offset)
            for element in [a-1 for a in cipher]:
                ciphertext += plaintext[offset+element]
            ciphertext += " "
        return ciphertext[:-1]



    def left_shift_(self,binary_str, positions):
        ## Left_shift hace un corrimiento de una posicion a la izquierda, notese que la entrada es un numero binario (str)
        ciphertext = ""
        if positions ==1:
            cipher=[2,3,4,5,1]
        else:
            cipher=[3,4,5,1,2]

        for offset in range(0, len(binary_str), len(cipher)):
            #print(offset)
            for element in [a-1 for a in cipher]:
                ciphertext += binary_str[offset+element]
            ciphertext += " "
        return ciphertext[:-1]
        
    def read_text(self,message):
        plaintext = self.text_to_bits(message)
        n = 8   
        blocks = [plaintext[i:i+n] for i in range(0, len(plaintext), n)]
        list_ecnrypted = list(map(self.SDES,blocks))
        print('Bloques Encriptados: ')
        print(list_ecnrypted)
        Decrypted = list(map(self.SDES_decrypt,list_ecnrypted))

        return list(map(self.text_from_bits,Decrypted))

    def text_to_bits(self,text, encoding='utf-8', errors='surrogatepass'):
        bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
        return bits.zfill(8 * ((len(bits) + 7) // 8))


    def text_from_bits(self,bits, encoding='utf-8', errors='surrogatepass'):
        n = int(bits, 2)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'

    def _keySchedule_(self,key):
        key = self.permutate_([3,5,2,7,4,10,1,9,8,6],key)
        key_1 = key[0:5]  #Key 1
        key_2 = key[5:10] #Key 2
        key_1 = self.left_shift_(key_1,1)
        key_2 = self.left_shift_(key_2,1)
        key_1merge = key_1 + key_2
        key_1merge_compress =self.permutateSimple_([6,3,7,4,8,5,10,9],key_1merge)
        
        #Para la key 2 tenemos
        key_1 = self.left_shift_(key_1,2)
        key_2 = self.left_shift_(key_2,2)
        key_2merge =key_1+key_2
        key_2merge_compress = self.permutateSimple_([6,3,7,4,8,5,10,9],key_2merge)

        return key_1merge_compress , key_2merge_compress


    def permutateSimple_(self,cipher, plaintext):
        ciphertext = ""
        for element in [a-1 for a in cipher]:
            ciphertext += plaintext[element]
        return ciphertext

    def xor(self,x, y):
        return '{1:0{0}b}'.format(len(x), int(x, 2) ^ int(y, 2))

    def SDES(self,m):
        key1, key2 = self._keySchedule_('1010000010')
        initial_per = self.permutateSimple_([2,6,3,1,4,8,5,7],m)
        L = initial_per[0:4]
        R = initial_per[4:8]
        R_xpand = self.permutateSimple_([4,1,2,3,2,3,4,1],R)
        k1_xor = self.xor(R_xpand,key1)
        xor_left_bits = k1_xor[0:4]
        xor_right_bits = k1_xor[4:8]
        renglon_1 = xor_left_bits[0]+xor_left_bits[-1]
        columna_1 = xor_left_bits[1]+xor_left_bits[2]
        first = self.find_Sbox(renglon_1, columna_1, self.Array)
        renglon_2 = xor_right_bits[0]+xor_right_bits[-1]
        columna_2 = xor_right_bits[1]+xor_right_bits[2]
        second = self.find_Sbox(renglon_2, columna_2, self.Array_2)
        permutationP4 = self.permutateSimple_([2,4,3,1], first+second)
        L = self.xor(permutationP4, L)
        #Ronda 2
        LR = R+L
        L=LR[0:4]
        R=LR[4:8]
        xpanded_R = self.permutateSimple_([4,1,2,3,2,3,4,1],LR[4:8])
        k2_xor = self.xor(xpanded_R,key2)
        xor_left_bits = k2_xor[0:4]
        xor_right_bits = k2_xor[4:8]
        renglon_1 = xor_left_bits[0]+xor_left_bits[-1]
        columna_1 = xor_left_bits[1]+xor_left_bits[2]
        first = self.find_Sbox(renglon_1, columna_1, self.Array)
        renglon_2 = xor_right_bits[0]+xor_right_bits[-1]
        columna_2 = xor_right_bits[1]+xor_right_bits[2]
        second = self.find_Sbox(renglon_2, columna_2, self.Array_2)
        permutationP4 = self.permutateSimple_([2,4,3,1], first+second)
        xorRL = self.xor(permutationP4,L)
        sub = xorRL+ R
        sub = self.permutateSimple_([4,1,3,5,7,2,8,6], sub)
        return sub


    def SDES_decrypt(self,m):
        key2, key1 = self._keySchedule_('1010000010')
        initial_per = self.permutateSimple_([2,6,3,1,4,8,5,7],m)
        L = initial_per[0:4]
        R = initial_per[4:8]
        R_xpand = self.permutateSimple_([4,1,2,3,2,3,4,1],R)
        k1_xor = self.xor(R_xpand,key1)
        xor_left_bits = k1_xor[0:4]
        xor_right_bits = k1_xor[4:8]
        renglon_1 = xor_left_bits[0]+xor_left_bits[-1]
        columna_1 = xor_left_bits[1]+xor_left_bits[2]
        first = self.find_Sbox(renglon_1, columna_1, self.Array)
        renglon_2 = xor_right_bits[0]+xor_right_bits[-1]
        columna_2 = xor_right_bits[1]+xor_right_bits[2]
        second = self.find_Sbox(renglon_2, columna_2, self.Array_2)
        permutationP4 = self.permutateSimple_([2,4,3,1], first+second)
        L = self.xor(permutationP4, L)
        #Ronda 2
        LR = R+L
        L=LR[0:4]
        R=LR[4:8]
        xpanded_R = self.permutateSimple_([4,1,2,3,2,3,4,1],LR[4:8])
        k2_xor = self.xor(xpanded_R,key2)
        xor_left_bits = k2_xor[0:4]
        xor_right_bits = k2_xor[4:8]
        renglon_1 = xor_left_bits[0]+xor_left_bits[-1]
        columna_1 = xor_left_bits[1]+xor_left_bits[2]
        first = self.find_Sbox(renglon_1, columna_1, self.Array)
        renglon_2 = xor_right_bits[0]+xor_right_bits[-1]
        columna_2 = xor_right_bits[1]+xor_right_bits[2]
        second = self.find_Sbox(renglon_2, columna_2, self.Array_2)
        permutationP4 = self.permutateSimple_([2,4,3,1], first+second)
        xorRL = self.xor(permutationP4,L)
        sub = xorRL+ R
        sub = self.permutateSimple_([4,1,3,5,7,2,8,6], sub)
        return sub