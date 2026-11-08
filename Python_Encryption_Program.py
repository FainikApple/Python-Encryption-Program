# These import main operating functions that are basically running the whole file of the algorithm.
#__________________________________________________________________________________________________

from AES_Encryption import AES_ENCRYPTION_PROGRAM
from Magma_Encryption import MAGMA_ENCRYPTION_PROGRAM
from RSA_Encryption import RSA_ENCRYPTION_PROGRAM

#__________________________________________________________________________________________________
print('')
print("______________________________________________________________________________________PYTHON ENCRYPTION PROGRAM______________________________________________________________________________________")
print('')

print("Greetings! This program is made for encrypting/decrypting various data using AES, RSA and Magma encryption algorithms.")
print('')

program_cycle_continue = True

while program_cycle_continue:
    decision = input("Please, type in which of the mentioned algorithms you would like to use (AES, RSA or Magma), otherwise type in 'shutdown' to stop the program from running. ----> ")
    print('')

    if decision.lower() == "aes":
        AES_ENCRYPTION_PROGRAM()

    elif decision.lower() == "rsa":
        RSA_ENCRYPTION_PROGRAM()

    elif decision.lower() == "magma":
        MAGMA_ENCRYPTION_PROGRAM()

    elif decision.lower() == "shutdown":
        raise Exception('User initiated program shutdown. Thanks for using the program.')

    else:
        print('The entered data cannot be used to initiate any existing commands. Please try again.')
        print('')   



