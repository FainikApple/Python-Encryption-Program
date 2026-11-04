# "PI" table with constant values. Used for encryption.
PI = [
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
]

# Mask for addition of module of 2 in 32 power.
MASK32 = 0xFFFFFFFF

#--------------------------------------------------------------

# Managing keys so that they would be EXACTLY 32 symbols long.
# That specific length is mandatory for the encryption and
# decryption to work.
def key_management(key:str) -> str:
    if len(key) == 32:
        return key
    elif len(key) < 32:
        return key + '#' * (32-len(key))
    else:
        return key[:32]
    
#--------------------------------------------------------------
    
# Managing data so that it can be divided by 8. This is mandatory
# for encryption and decryption to work properly.
def data_management(data:str) -> str:
    while len(data) % 8 != 0:
        data += ' '
    return data

#--------------------------------------------------------------

# Formation of encrypted blocks of data, appends a part of data
# it's working with using slices and then encodes using "utf-8".
def formation_of_blocks(data:str) -> list:
    blocks_of_data = []
    while len(data) > 0:
        blocks_of_data.append(str(data[:8]).encode("utf-8"))
        data = data[8:]
    return blocks_of_data

def formation_of_enc_blocks(data:str) -> list:
    blocks_of_data = []
    while len(data) > 0:
        blocks_of_data.append(bytes.fromhex(str(data[:16])))
        data = data[16:]
    return blocks_of_data

#--------------------------------------------------------------

# Using "xor" operation to add a couple arguments together.
def add(a:int, b:int) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Adding two arguments together using the mask (its functionality
# is listed in the start of the code).
def add_32(a:bytes, b:bytes) -> bytes:
    a = int.from_bytes(a, "big")
    b = int.from_bytes(b, "big")
    return ((a + b) & MASK32).to_bytes(4, "big")

#--------------------------------------------------------------

# Works with data (bytes type). We first create "res" variable,
# which will be an array of bytes with the size of "4". Then, using
# cycle and variables "part_1" and "part_2" we each give them certain
# parts of the data and then further change them using the PI table of
# constant values. We then change "res" bytearray using the just changed
# "part_1" and "part_2" variables and after the cycle ends return the byte
# array.
def t_operation(data:bytes) -> int:
    res = bytearray(4)
    for i, byte in enumerate(data):
        part_1 = (byte >> 4) & 0x0F
        part_2 = byte & 0x0F

        part_1 = PI[i * 2][part_1]
        part_2 = PI[i * 2 + 1][part_2]

        res[i] = (part_1 << 4) | part_2
    return bytes(res)

#--------------------------------------------------------------

# Works with variables "a" and "b" (byte type). We create "temp" variable
# and give it the value of "add_32" function with the variables "a" and "b".
# Then we use "t_operation" which works with "temp" and give the result to
# "value" variable. After that we turn "value" into integer using the bytes
# stored in it and rotate the data by 11 positions using a mask. Finally, we
# convert to the resulting "value" to bytes and return it.
def g_operation(a:bytes, b:bytes) -> bytes:
    temp = add_32(b, a) # Sum of module 2 in 32 power
    value = t_operation(temp)
    value = int.from_bytes(value, "big")
    value = ((value << 11) | (value >> (32 - 11))) & MASK32 #11 position rotation with mask
    return value.to_bytes(4, "big")

#--------------------------------------------------------------

# Generates 32 iteration keys for encryption and decryption using
# the key ("k" variable). Each iteration key is 4 symbols long.
def key_schedule(k:bytes) -> list:
    iter_keys = [
        k[i:i + 4]
        for i in range(0, 32, 4)
    ]
    return iter_keys * 3 + iter_keys[::-1]

#--------------------------------------------------------------

# This operation is a basic encrypting or decrypting step, 
# where "k" variable is a key and "block" is a block of data.
def G_operation(k:bytes, block:bytes) -> bytes:
    a1 = block[:4] # left part of the block
    a2 = block[4:] # right part of the block
    g_value = g_operation(k, a2)
    new_a2 = add(a1, g_value)
    return a2 + new_a2

# The last step during encryption or decryption.
def G_final_operation(k:bytes, block:bytes) -> bytes:
    a1 = block[:4] # left part of the block
    a2 = block[4:] # right part of the block
    g_value = g_operation(k, a2)
    new_a1 = add(a1, g_value)
    return new_a1 + a2

#--------------------------------------------------------------

# Encryption of the data. We first generate iteration keys using
# "key_schedule" function, then make "state" variable and give it
# the value of "block" variable, so that it's easier to navigate here.
# The "state" variable goes through the cycle, changing each time the
# "G_operation" function is called. Finally, we return the encrypted block of
# data ("state" variable) after calling "G_final_operation" function.
def magma_encryption(k:bytes, block:bytes) -> bytes:
    iter_keys_list = key_schedule(k)
    state = block
    for i in range(31):
        state = G_operation(iter_keys_list[i], state)
    return G_final_operation(iter_keys_list[31], state)

# Decryption of data. Not so different from the previous function,
# only the flow of the cycle and the choice of iteration keys had
# been changed.
def magma_decryption(k:bytes, block:bytes) -> bytes:
    iter_keys_list = key_schedule(k)
    state = block
    for i in range(31, 0, -1): # start : 31, step : -1
        state = G_operation(iter_keys_list[i], state)
    return G_final_operation(iter_keys_list[0], state)

#______________________________________________MAIN PROGRAM______________________________________________

#_____________________________________________USED VARIABLES_________________________________________

# plain_txt = ''                                 Data, which would be encrypted.
# key = ''                                       Key, which is used for encryption or decryption.
# blocks_of_data = []                            List of blocks of data.
# enc_blocks_of_data = []                        List of blocks of encrypted data.
# cipher_key = ''                                Encoded key which is used during encryption.
# encrypt_res = ''                               Result of encryption.
# decrypt_res = ''                               Result of decryption.
# program_cycle_continue = True/False            Determines whether the program continues running or stops entirely.   

#____________________________________________________________________________________________________

print("___________________________________________MAGMA ENCRYPTION PROGRAM______________________________________________")
print('')

program_cycle_continue = True

while program_cycle_continue:
    decision = input('Would you like to encrypt, decrypt data or exit the program entirely? ----> ')

    if decision.lower() == 'encrypt':
        print('')

        # Typing in the data and the key. 
        plain_txt = input('Type in the data you want to get encrypted ----> ')
        key = input('Type in the key which will be used for encryption (the length of the key has to be EXACTLY 32 symbols long) ----> ')

        # Managing the length of data and the key.
        plain_txt = data_management(plain_txt)
        key = key_management(key)

        # Forming blocks of data and encoding the key (converting to bytes).
        blocks_of_data = formation_of_blocks(plain_txt)
        cipher_key = str(key).encode('utf-8')

        # Encrypting.
        encrypt_res = ''
        for i in range (len(blocks_of_data)):                                      
            res = magma_encryption(cipher_key, blocks_of_data[i])
            encrypt_res = encrypt_res + res.hex()
            res = ''

        # Printing results.
        print('')
        print('_______________________________________________ENCRYPTION RESULTS_______________________________________________')
        print('')
        print('Initial data :', plain_txt)
        print('Key, which was used for encryption :', cipher_key.hex())
        print('Encrypted data :', encrypt_res)
        print('________________________________________________________________________________________________________________')
        print('')

    elif decision.lower() == 'decrypt':
        print('')

        # Typing in encrypted data and encoded key (whilst checking if the user following the requirements).
        enc_text = input('Type in the encrypted data ----> ')
        while len(enc_text) % 8 != 0:
            enc_text = input("Sorry, cannot accept this data as it can't be divided by 8. Please, try again ----> ")

        key = input('Type in the key, which was used for encryption (please note, that the key has to be EXACTLY 64 symbols long) ----> ')
        while len(key) != 64:
            key = input("Sorry, cannot accept this key as it doesn't match the required length. Please, try again ----> ")

        # Forming blocks of encrypted data and converting back to bytes the key.
        enc_blocks_of_data = formation_of_enc_blocks(enc_text)
        key = bytes.fromhex(key)

        # Decrypting.
        decrypt_res = ''
        for i in range (len(enc_blocks_of_data)):
            res = magma_decryption(key, enc_blocks_of_data[i])
            decrypt_res = decrypt_res + res.hex()
            res = ''

        # Printing results
        print('')
        print('_______________________________________________DECRYPTION RESULTS_______________________________________________')
        print('')
        print('Initial encrypted data :', enc_text)
        print('Key, which was used for decryption :', key.hex())
        print('Decrypted data :', bytes.fromhex(decrypt_res).decode())
        print('________________________________________________________________________________________________________________')
        print('')

    elif decision.lower() == 'exit':
        program_cycle_continue = False        