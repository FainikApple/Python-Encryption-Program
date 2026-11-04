import random

# Uses Eiler multiplication formula.
def Eiler_func(x:int, y:int) -> int:
    multiply = (x-1) * (y-1)
    return multiply

# All it does is checking if the number is prime
# or not, so it returns either "True" or "False".
def Is_Prime(x:int) -> bool:
    if x < 2:
        return False
    for i in range(2, int(x ** 0.5) + 1):
        if x % i == 0:
            return False
    return True    

# Generates a random number and checks if this number
# is a prime number using previous function. If it is,
# the function returns this number, otherwise it continues
# until the number generated is a prime.
def Prime_Randomizer(x:int) -> int:
    while True:
        x = random.randint(1, 1000)
        if Is_Prime(x):
            return x

# "Mutually simple" means that variable "x" is smaller
# than variable "y" and that they don't have any mutual
# divisors other than "1" and themselves.
def Mutually_Simple(x:int, y:int) -> int:
    while True:
        stopper = True
        x = Prime_Randomizer(x)
        if x < y:
            for i in range(2, y-1):
                if x % i == 0 and y % i == 0:
                    stopper = False
                    break
            if stopper == True:
                return x
            else:
                continue
        elif x >= y:
            continue

# Works with variables "ch1" and "ch2" where the first one takes
# a value from a "e" variable and another takes value from a
# "eN" variable (these variable are used in the main part of
# the whole program). The whole goal is to find a value, which
# if multiplied by "ch1" and divided by "ch2" would give us the
# remainder equal to "1". For this, we are using advanced Euclid
# algorithm.
def Opposite_of_Module(ch1:int, ch2:int) -> int:
    r1 = ch2
    r2 = ch1
    x1 = 0
    x2 = 1
    while r2 != 0:
        q = r1 // r2
        # Save current values
        temp_r = r2
        temp_x = x2
        # Calculate new values
        r2 = r1 - q * r2
        x2 = x1 - q * x2
        # Shift values
        r1 = temp_r
        x1 = temp_x
    return x1 % ch2

# Creates a key (public or private one) with the given arguments.
def key_creation(key:list, arg_1:int, arg_2:int) -> list:
    key.append(arg_1)
    key.append(arg_2)
    return key

# Encrypting data with the given key and data.
def encrypting_data(key:list, data:int) -> int:
    return data ** key[0] % key[1]

# Decrypting data with the given key and encrypted data.
def decrypting_data(key:list, data:int) -> int:
    return data ** key[0] % key[1]

#____________________________________________________MAIN PROGRAM_____________________________________________

#________________________________________USED VARIABLES________________________________________________

# VERY IMPORTANT NOTE -----> This encryption algorithm is coded so that it will pick the numbers with which the data would be encrypted RANDOMLY(it's faster and easier to handle).

# p = 0                                     Prime number, used during encryption process.
# q = 0                                     Prime number, used during encryption process.
# eN = 0                                    Stores the result of Eiler function.
# e = 0                                     Used for creating public key.
# d = 0                                     Used for creating private key.
# n = 0                                     Used for creating both types of keys.
# enc_data = 0                              Encrypted data.
# dec_data = 0                              Decrypted data.
# priv_key = []                             Private key.
# public_key = []                           Public key.
# program_cycle_continue = True/False       Determines whether the program continues running or stops entirely.


#______________________________________________________________________________________________________

print("___________________________________________RSA ENCRYPTION PROGRAM______________________________________________")
print('')

program_cycle_continue = True

while program_cycle_continue:
    decision = input('Would you like to encrypt, decrypt data or exit the program entirely? ----> ')

    if decision.lower() == 'encrypt':
        print('')

        # Typing in plain data.
        data = int(input('Type in the information you want to get encrypted (must be numbers, big numbers need more time for them to get encrypted) ----> '))

        # Generating two prime numbers and then multiplying them.
        p, q = 0, 0
        p = Prime_Randomizer(p)
        q = Prime_Randomizer(q)
        n = p * q

        # Using Eiler function.
        eN = Eiler_func(p, q)

        # Picking the numbers 'e' and 'd' according to their particular details.
        e = 0
        e = Mutually_Simple(e, eN)
        d = Opposite_of_Module(e, eN)

        # Producing public and private keys.
        public_key, priv_key = [], []
        public_key = key_creation(public_key, e, n)
        priv_key = key_creation(priv_key, d, n)

        # Encrypting.
        enc_data = encrypting_data(public_key, data)

        # Printing results.
        print('')
        print('_______________________________________________ENCRYPTION RESULTS_______________________________________________')
        print('')
        print('Initial data :', data)
        print('Private key :', priv_key[0], ',', priv_key[1])
        print('Encrypted data :', enc_data)
        print('________________________________________________________________________________________________________________')
        print('')

    elif decision.lower() == 'decrypt':
        print('')

        # Typing in encrypted data.
        enc_data = int(input('Type in the encrypted data ----> '))

        # Typing in and forming private key.
        print('Type in the values of private key (in the SAME sequence) :')
        val1 = int(input('First value of the private key ----> '))
        val2 = int(input('Second value of the private key ----> '))
        priv_key = []
        priv_key.append(val1)
        priv_key.append(val2)

        # Decrypting data.
        dec_data = decrypting_data(priv_key, enc_data)

        # Printing results.
        print('')
        print('_______________________________________________DECRYPTION RESULTS_______________________________________________')
        print('')
        print('Initial encrypted data :', enc_data)
        print('Private key, which was used for decryption :', priv_key[0], ',', priv_key[1])
        print('Decrypted data :', dec_data)
        print('________________________________________________________________________________________________________________')
        print('')

    elif decision.lower() == 'exit':
        program_cycle_continue = False   