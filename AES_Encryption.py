# 10 class

# Brave soldiers who were used for mandatory testing (lowk caring)
'''
#___________________________________________________
state_test =   [["19","a0","9a","e9"],
                ["3d","f4","c6","f8"],
                ["e3","e2","8d","48"],
                ["be","2b","2a","08"]]

round_key_test =   [["2b","28","ab","09"],
                    ["7e","ae","f7","cf"],
                    ["15","d2","15","4f"],
                    ["16","a6","88","3c"]]
#___________________________________________________
'''

# If the typed in text cannot be divided by 16 (which is mandatory for creating states), 
# spaces would be added to the text until it matches the requirement.
def till_divided_by_16 (line:str) -> str:
    while len(line) % 16 != 0:
        line += ' '
    return line

# The key has to be 16 symbols long or 128 bit. Here the key is modified to be either longer or shorter.
def till_equal_16 (line:str) -> str:
    if len(line) > 16:
        line = line[:len(line) - 16]
    elif len(line) < 16:
        line += '#' * (16 - len(line))
    return line

# Used during pre-decryption phase.
def form_two_symbol_list(key:str) -> list:
    list_of_key_elements = []
    while len(key) > 0:
        list_of_key_elements.append(key[:2])
        key = key[2:]
    return list_of_key_elements

# Used during pre-encryption phase.
def form_used_key(k_list:list) -> list:
    str_value = ''
    for i in k_list:
        str_value = str_value + i    
    return str_value

# Turns the data to bytes and then makes it hex. Basically creates
# a basic setup for encrypting (hex also polishes data, so it doesn't
# look like a tangled mass of symbols).
def turn_to_hex (line:str) -> str:
    enc_line = line.encode("utf-8")
    hex_line = enc_line.hex(' ')
    return hex_line

# Generates a list of states. States hold 128 bits of information (basically 16 pairs of symbols in each state).
def state_collection(line:str) -> str:
    collection = []
    ex_state = []
    ex_state_row = []
    while len(line) >= 16:
        ex_state = []
        for i in range(4):
            ex_state_row = line[:4]
            line = line[4:]
            ex_state.append(ex_state_row)
        collection.append(ex_state)    
    return collection

# Generates round key using the modified key. These are to be used during encryption in the add_round_key function (followed further next).
def round_key_formation(line:str) -> str:
    r_key = []
    r_row = []
    while len(line) > 0:
        r_row = line[:4]
        line = line[4:]
        r_key.append(r_row)
    return r_key   

# Whole purpose is to form columns in Key Schedule function.
def clmn_form(list:list, pos:int) -> list:
    column = []
    for row in range(4):
        byte = list[row][pos]
        column.append(byte)
    return column

# Reforming lists. Used during key schedule to avoid potential errors during encryption
# (the whole AES holds onto columns but the project is written using rows, oops).
def reform_list(list:list) -> list:
    new_list = []
    new_row = []
    for i in range(4):
        for j in range(4):
            new_row.append(list[j][i])
        new_list.append(new_row)
        new_row = []
    return new_list

# ___________________________________________TRANSFORMATIONS______________________________________________

# Works with the current state and sbox (table with constant values).
# Basically takes rows in states and then bytes (which are hex'ed) in those rows. We then lowercase
# the bytes and take them apart. After that we store those parts in variables r (means row) and clmn
# and convert them to integers. Finally, by using the integers we find new bytes in sbox and replace the old
# bytes (reffering to the ones in states) with the new ones until the entire state has changed.
def sub_bytes(state:list, sbox:list) -> list:
    new_state = []
    for row in state:
        ex_row = []
        for byte in row:
            byte.lower()
            r = int(byte[0], 16)
            clmn = int(byte[1], 16)
            ex_row.append(sbox[r][clmn])
        new_state.append(ex_row)
    return new_state

# Acts the same as his "older brother" except it's
# mainly used in Key Schedule and it works with the columns,
# not with the whole state.
def special_sub_bytes(clmn:list, sbox:list) -> list:
    new_clmn = []
    for byte in clmn:
        byte.lower()
        r = int(byte[0], 16)
        clmn = int(byte[1], 16)
        new_clmn.append(sbox[r][clmn])
    return new_clmn

# Works with the current state. All it does is shifting bytes. 
# First row is unchanged. The following rows are changed according to their index, 
# so for row with index "1" we just take the "i" variable as "1" and use slices to change the row 
# (this implies to every other following row).
def shift_rows(state:list) -> list:
    new_state = []
    i = 0
    for row in state:
        new_row = []
        new_row = row[i:] + row[:i]
        new_state.append(new_row)
        i += 1
    return new_state

# Works with the current state. Quite tricky to say the least.
# Using s with go through the state, then we set up the "result" variable which stores an
# empty matrix. After that in a following cycle we give the variables "a0" to "a3" data
# from the state using s. Functions m2 and m3 are used for matrix multiplication using
# Galua Map (2 ^ 8, scary thingy). Finally, we fill up the "result" with new data using
# m2 and m3 functions which xor's with data from the state (previous cycle) and return 
# the resulting new-state (format method deletes the useless part of data after working
# with it).
def mix_columns(state:list) -> list:
    s = [[int(x, 16) for x in row] for row in state]    

    result = [[0]*4 for _ in range(4)]

    for column in range(4):
        a0 = s[0][column]
        a1 = s[1][column]
        a2 = s[2][column]
        a3 = s[3][column]

        def m2(x):
            return((x << 1) ^ 0x1b) & 0xff if x & 0x80 else (x << 1)
        
        def m3(x):
            return m2(x) ^ x
        
        result[0][column] = m2(a0) ^ m3(a1) ^ a2 ^ a3
        result[1][column] = a0 ^ m2(a1) ^ m3(a2) ^ a3
        result[2][column] = a0 ^ a1 ^ m2(a2) ^ m3(a3)
        result[3][column] = m3(a0) ^ a1 ^ a2 ^ m2(a3)
    return [[format(x, '02x') for x in row] for row in result]
    
# Add Round Key transformation. Works with the current state and round key.
# Just xor's the data from the state and round key. Then returns the new state.
def add_round_key(state:list, round_key:list) -> list:
    s = [[int(x, 16) for x in row] for row in state]
    x = [[int(x, 16) for x in row] for row in round_key]

    return [[format(s[i][j] ^ x[i][j], '02x') for j in range(4)] for i in range(4)]

# Used during key_schedule. Shifts bytes in an array using slices.
def rot_word(array:list) -> list:
    array = array[1:] + array[:1]
    return array

# Used for creating round keys. Works with the typed-in key, rcon (table with constant values) and
# sbox. We first take two variables : "g" and "i", where "g" is the number of round keys and "i" is
# the amount of processed columns. Variables "clmn_1" and "clmn_2" are used to store currenlty processed
# columns. Depending on the "i" variable we use different methods to processing columns and creating
# new ones. After forming a new round key we reform it with "reform list" function so encryption process
# doesn't fumble (explained earlier) and then add it to the "list_of_round_keys" variable which stores
# the round keys.
def key_schedule(key:list, rcon:list, sbox:list) -> list:
    round_key = key
    new_round_key = []
    list_of_round_keys = []
    list_of_round_keys.append(key)
    for g in range(10):
        new_round_key = []
        for i in range(4):
            if i == 0:
                clmn_2 = special_sub_bytes(rot_word(clmn_form(round_key, i+3)), sbox)
                clmn_1 = clmn_form(round_key, i)
            else:
                clmn_2 = new_round_key[i-1]
                clmn_1 = clmn_form(round_key, i)

            c1 = [int(x, 16) for x in clmn_1]
            c2 = [int(x, 16) for x in clmn_2]
            if i == 0:
                c3 = [int(x, 16) for x in rcon[g]]

            if i == 0:
                new_clmn = [format(c1[x] ^ c2[x] ^ c3[x], '02x') for x in range (4)]
            else:
                new_clmn = [format(c1[x] ^ c2[x], '02x') for x in range (4)]

            new_round_key.append(new_clmn)
        new_round_key = reform_list(new_round_key)
        round_key = new_round_key
        list_of_round_keys.append(round_key)
    return list_of_round_keys

#___________________________________________INVERTED_TRANSFORMATIONS_________________________________________

# Inverted transformations are basically reversed version of main transformations but are used during decryption.
# With that being said, further information about these are not required.

# Inverted SubBytes
def inv_sub_bytes(state:list, inv_sbox:list) -> list:
    new_state = []
    for row in state:
        ex_row = []
        for byte in row:
            byte = byte.lower()
            r = int(byte[0], 16)
            clmn = int(byte[1], 16)
            ex_row.append(inv_sbox[r][clmn])
        new_state.append(ex_row)
    return new_state

# Inverted ShiftRows
def inv_shift_rows(state:list) -> list:
    new_state = []
    i = 0
    for row in state:
        new_row = []
        new_row = row[-i:] + row[:-i]
        new_state.append(new_row)
        i += 1
    return new_state

# Inverted MixColumns
def inv_mix_columns(state:list) -> list:
    s = [[int(x, 16) for x in row] for row in state]

    result = [[0]*4 for _ in range(4)]

    def mul(a, b): # Multiplying by Galua Map(2 ^ 8)
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            value = a & 0x80
            a = (a << 1) & 0xff
            if value:
                a ^= 0x1b
            b >>= 1
        return p

    for column in range(4):
        a0 = s[0][column]
        a1 = s[1][column]
        a2 = s[2][column]
        a3 = s[3][column]

        result[0][column] = mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09)
        result[1][column] = mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d)
        result[2][column] = mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b)
        result[3][column] = mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e)

    return [[format(x, '02x') for x in row] for row in result]

# AddRoundKey is its own inverse (can be used to encryption and decryption accordingly).

#__________________________________DECRYPTION/ENCRYPTION FUNCTIONS_______________________________

# AES Encryption function.
def AES_ENCRYPTION(sbox, rcon): 

    # Typing in data (text and key).
    plain_txt = input('Type in the text you want to get encrypted ----> ')

    print('')

    key = input('Now, type in the key with which your text will get encrypted (please note, that if the key is not EXACTLY 16 symbols long, then # symbols would be added to the key, to match the required length) ----> ')        

    # The process of modifying the typed in data (the text and the key).
    plain_txt = till_divided_by_16(plain_txt)
    key = till_equal_16(key)

    # Encoding and hex'ing key and text
    hex_key = turn_to_hex(key).split()
    hex_text = turn_to_hex(plain_txt).split()

    # Forming lists of states (from text) and lists of key (parts-like).
    s_collection = state_collection(hex_text)
    used_key = form_used_key(hex_key)
    key = round_key_formation(hex_key)

    # Forming a list of iteration keys.
    list_of_r_keys = key_schedule(key, rcon, sbox)

    # Encrypting
    enc_s_collection = []

    for g in s_collection:
        state = g
        state = add_round_key(state, list_of_r_keys[0])
        for i in range (1, 11, 1):
            state = sub_bytes(state, sbox)
            state = shift_rows(state)
            if i < 10:
                state = mix_columns(state)
            state = add_round_key(state, list_of_r_keys[i])
        enc_s_collection.append(state)

    enc_text = ''
    for i in enc_s_collection:
        for g in range(4):
            for j in range(4):
                enc_text = enc_text + i[g][j]

    # Printing results.
    print('')
    print('_____________________________________________________ENCRYPTION RESULTS_____________________________________________________')
    print('')
    print('Initial data :', plain_txt)
    print('Key, which was used for encryption :', used_key)
    print('Encrypted data :', enc_text)
    print('____________________________________________________________________________________________________________________________')
    print('')

    return 0

# AES Decryption function.
def AES_DECRYPTION(sbox, rcon, inv_sbox):

    # Typing in encrypted data (encrypted text and key) and checking if the user is following requirements.
    enc_text = input('Type in the encrypted data ----> ')
    while len(enc_text) % 16 != 0:
        print('')
        enc_text = input("Sorry, cannot accept this data as it can't be divided by 16. Please, try again ----> ")

    print('')    
    
    key = input('Type in the key, which was used for encryption (please note, that the key has to be EXACTLY 32 symbols long) ----> ')
    while len(key) != 32:
        print('')
        key = input("Sorry, cannot accept this key as it doesn't match the required length. Please, try again ----> ")

    # Forming a list of iteration keys.
    s_key = form_two_symbol_list(key)
    s_key = round_key_formation(s_key)
    list_of_r_keys = key_schedule(s_key, rcon, sbox)

    # Forming a list of encrypted data.
    init_enc_txt = enc_text
    enc_text = form_two_symbol_list(enc_text)
    enc_s_collection = state_collection(enc_text)

    # Decrypting.
    dec_s_collection = []

    for g in enc_s_collection:
        state = g
        state = add_round_key(state, list_of_r_keys[10])
        for i in range (9, -1, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state, inv_sbox)
            state = add_round_key(state, list_of_r_keys[i])
            if i > 0:
                state = inv_mix_columns(state)
        dec_s_collection.append(state)

    dec_text = ''
    for i in dec_s_collection:
        for g in range(4):
            for j in range(4):
                dec_text = dec_text + i[g][j]

    # Printing results.
    print('')
    print('_____________________________________________________DECRYPTION RESULTS_____________________________________________________')
    print('')
    print('Initial encrypted data :', init_enc_txt)
    print('Key, which was used for decryption :', key)
    print('Decrypted data :', bytes.fromhex(dec_text).decode())
    print('____________________________________________________________________________________________________________________________')
    print('')

    return 0

#_________________________________________MAIN OPERATING FUNCTION__________________________________

def AES_ENCRYPTION_PROGRAM():

    print("_____________________________________________________AES ENCRYPTION ALGORITHM_____________________________________________________")
    print('')

    program_cycle_continue = True

    while program_cycle_continue:
        decision = input("Would you like to encrypt, decrypt data or exit the algorithm entirely? ----> ")

        if decision.lower() == 'encrypt':
            print('')
            AES_ENCRYPTION(sbox, rcon)

        elif decision.lower() == 'decrypt':
            print('')
            AES_DECRYPTION(sbox, rcon, inv_sbox)
            
        elif decision.lower() == 'exit':
            print('__________________________________________________________________________________________________________________________________')
            print('')
            program_cycle_continue = False

        else:
            print('')
            print('The entered data cannot be used to initiate any existing commands. Please try again.')
            print('')    

    return 0            

#__________________________________TABLES WITH CONSTANT VALUES____________________________________

# For SubBytes transformation and Key Schedule (encryption process)
sbox = [["63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"],
        ["ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"],
        ["b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"],
        ["04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"],
        ["09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"],
        ["53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"],
        ["d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"],
        ["51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"],
        ["cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"],
        ["60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"],
        ["e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"],
        ["e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"],
        ["ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"],
        ["70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"],
        ["e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"],
        ["8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"]]

# For decrypting data (decryption process)
inv_sbox = [["52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"],
            ["7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"],
            ["54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"],
            ["08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"],
            ["72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"],
            ["6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"],
            ["90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"],
            ["d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"],
            ["3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"],
            ["96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"],
            ["47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"],
            ["fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"],
            ["1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"],
            ["60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"],
            ["a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"],
            ["17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"]]

# For Key Schedule
rcon = [['01', '00', '00', '00'],
        ['02', '00', '00', '00'],
        ['04', '00', '00', '00'],
        ['08', '00', '00', '00'],
        ['10', '00', '00', '00'],
        ['20', '00', '00', '00'],
        ['40', '00', '00', '00'],
        ['80', '00', '00', '00'],
        ['1b', '00', '00', '00'],
        ['36', '00', '00', '00']]

#________________________________________USED VARIABLES___________________________________________
# NOTE --> The following variables are used in encryption/decryption AES functions and the main operating function. These are displayed here for convenience.

# hex_key = ''                                  Hex key.
# hex_text = ''                                 Hex text.
# s_collection = []                             List of states.
# key = ''                                      Proper formation of a key.
# list_of_r_keys = []                           List of round keys produced for the encryption.
# enc_text = ''                                 Encrypted data.
# dec_text = ''                                 Decrypted data.
# init_enc_txt = ''                             Initial encrypted data, only used during decryption.
# enc_s_collection = []                         List of encrypted states or, in other words, encrypted data.
# dec_s_collection = []                         Same as the last one, but these are decrypted states.
# list_of_r_keys = []                           Used for storing generated round keys.
# program_cycle_continue = True/False           Determines whether the program continues running or stops entirely.

#_________________________________________________________________________________________________

# AES_ENCRYPTION_PROGRAM() # The start of the whole program.