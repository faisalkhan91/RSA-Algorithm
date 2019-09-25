#!/usr/bin/python3

#############################################################################################
#                               Program by Mohammed Faisal Khan                             #
#                               Email: faisalkhan91@outlook.com                             #
#                               Created on November 6, 2017                                 #
#############################################################################################

# Importing modules

import random

# Function Definitions

'''
Reference: https://linuxconfig.org/function-to-check-for-a-prime-number-with-python
Function to validate if the number is prime
'''


def check_prime(x):
    if x >= 2:
        for y in range(2, x):
            if not (x % y):
                return False
    else:
        return False
    return True


'''
Euclid's algorithm for determining the greatest common divisor
'''


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


'''
Euclid's extended algorithm for finding the multiplicative inverse of two numbers
'''


def multiplicative_inverse(a, b):
    """
    Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space

    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a

    # return a , lx, ly  # Return only positive values
    return lx


'''
Reference : https://stackoverflow.com/questions/40578553/fast-modular-exponentiation-help-me-find-the-mistake
Fast modular exponentiation function
'''


def get_mod_expo(base, exponent, modulus):
    result = 1
    while exponent:
        exponent, d = exponent // 2, exponent % 2
        if d:
            result = result * base % modulus
        base = base * base % modulus
    return result


'''
Function to generate a public and private key pair
'''


def generate_keypair(p, q):
    if not (check_prime(p) and check_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal!')
    # n = p * q
    n = p * q
    print("Value of n (where, n = p * q) is: ", n)

    # Phi is the totient of n
    phi = (p-1)*(q-1)
    print("Value of phi(n) (where, phi(n) = (p-1)*(q-1)) is: ", phi)

    # Choose an integer e such that e and phi(n) are co-prime
    # e = random.randrange(1, phi)
    print("Enter e such that is co-prime to ", phi, ": ")
    e = int(input())

    # Use Euclid's Algorithm to verify that e and phi(n) are co-prime
    g = gcd(e, phi)
    if g != 1:
        print("The number you entered is not co-prime, Please enter e such that is co-prime to ", phi, ": ")
        e = int(input())
    print("Value of e entered is: ", e)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)
    print("Value of d is: ", d)

    # Return public and private key-pair
    # Public key is (e, n) and private key is (d, n)
    return (e, n), (d, n)


'''
Function to Encrypt the message
'''


def encrypt(public_key, to_encrypt):

    # Unpack the key into it's components
    key, n = public_key

    # To get the encrypted message using Fast Modular Exponentiation
    cipher = get_mod_expo(to_encrypt, key, n)

    # Return the array of bytes
    return cipher


'''
Function to Decrypt the message
'''


def decrypt(private_key, to_decrypt):

    # Unpack the key into its components
    key, n = private_key

    # To get the decrypted message using Fast Modular Exponentiation

    decrypted = get_mod_expo(to_decrypt, key, n)

    # Return the array of bytes as a string
    return decrypted


#############################################################################################

# Main Program

# RSA Encryption/Decryption Algorithm
print("\n######## RSA Encryption/Decryption Algorithm #########\n")
p = int(input("Enter a prime number (p: 7, 11, 23, etc): "))
q = int(input("Enter another prime number (q: 5, 13, 19, etc [Not same as above]): "))
print("Prime numbers entered, p: ", p, " and q: ", q)

print("Generating Public/Private key-pairs!")
public, private = generate_keypair(p, q)
print("Your public key is ", public, " and your private key is ", private)

message = int(input("Enter the message to be encrypted: "))
print("Message to be encrypted (M): ", message)

encrypted_msg = encrypt(public, message)
print("Encrypted message (C): ", encrypted_msg)

decrypted_msg = decrypt(private, encrypted_msg)
print("Message decrypted (M'): ", message)

#############################################################################################
#                                       End of Program                                      #
#                                     Copyright (c) 2017                                    #
#############################################################################################
