# Write your own functions for encrypting messages and decrypting ciphertexts using AES encryption
# in CBC and CTR mode. You are allowed to call the AES block encryption/decryption functions from
# the library, but you should implement the CBC and CTR mode operations yourself.

from Alex_Lobrano_implementation import *

key = os.urandom(16)
iv = os.urandom(16)
ctr = os.urandom(16)
msg = generate_message(16)
backend = default_backend()

##################### CBC #####################
print "Message:", msg

my_ciphertext = cbc_encrypt(key,iv,msg)
my_plaintext = cbc_decrypt(key,iv,my_ciphertext)

print "\nCBC:"
print "My encryption:      " + my_ciphertext.encode('hex')
print "My decryption:      " + my_plaintext

##################### CTR #####################
my_ciphertext = ctr_encrypt(key,ctr,msg)
my_plaintext = ctr_decrypt(key,ctr,my_ciphertext)

print "\nCTR:"
print "My encryption:      " + my_ciphertext.encode('hex')
print "My decryption:      " + my_plaintext