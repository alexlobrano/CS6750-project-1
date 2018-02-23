import os
import sys
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import CipherBackend

key = os.urandom(16)
iv = os.urandom(16)
ctr = os.urandom(16)
msg = "1234567890123456"
backend = default_backend() 

def xor(string1, string2):
	array1 = bytearray(string1)
	array2 = bytearray(string2)
	xor_array = bytearray(len(string1))
	xor_str = ""
	for i in range(len(array1)):
		xor_array[i] = array1[i]^array2[i]
	for i in range(len(array1)):
		xor_str += str(chr(xor_array[i]))
	return xor_str

def fix_leading_zeroes(ctr,total_bytes):
	leading_zeroes = 16*total_bytes - len(ctr)
	if(leading_zeroes):
		print "Fixing ctr"
		for i in range(0,leading_zeroes):
			ctr = "0" + ctr
	return ctr
	
def cbc_encrypt(key, iv, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend)
	encryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	cipher_array = [None] * total_bytes
	
	#byte 1
	cipher_array[0] = encryptor.update(xor(iv,msg[0:16]))
	cipher_text = cipher_array[0]
	
	#rest of bytes
	for i in range(1,total_bytes):
		cipher_array[i] = encryptor.update(xor(cipher_array[i-1],msg[i*16:(i+1)*16]))
		cipher_text += cipher_array[i]
	return cipher_text
	
def cbc_decrypt(key, iv, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend)
	decryptor = cipher.decryptor()
	
	total_bytes = (len(msg)/16)
	plaintext_array = [None] * total_bytes
	
	#byte 1
	plaintext_array[0] = xor(decryptor.update(msg[0:16]),iv)
	plaintext = plaintext_array[0]
	
	#rest of bytes
	for i in range(1,total_bytes):
		plaintext_array[i] = xor(decryptor.update(msg[(i)*16:(i+1)*16]),msg[(i-1)*16:i*16])
		plaintext += plaintext_array[i]
	return plaintext	
	
def ctr_encrypt(key, ctr, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend)
	encryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	cipher_array = [None] * total_bytes
	
	#byte 1
	cipher_array[0] = xor(msg[0:16],encryptor.update(ctr))
	cipher_text = cipher_array[0]
	
	#rest of bytes
	for i in range(1,total_bytes):
		ctr = int(ctr.encode('hex'), 16) + 1			# encode ctr bytes string as hex string, convert to int, increment by 1
		ctr = format(ctr, 'x')							# format ctr as hex string
		ctr = fix_leading_zeroes(ctr,total_bytes)		# check if leading zeroes need to be added
		ctr = ctr.decode('hex')							# decode hex string back to bytes string
		cipher_array[i] = xor(msg[i*16:(i+1)*16],encryptor.update(ctr))
		cipher_text += cipher_array[i]
	return cipher_text
	
def ctr_decrypt(key, ctr, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend)
	decryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	plaintext_array = [None] * total_bytes
	
	#byte 1
	plaintext_array[0] = xor(decryptor.update(ctr),msg[0:16])
	plaintext = plaintext_array[0]

	#rest of bytes
	for i in range(1,total_bytes):
		ctr = int(ctr.encode('hex'), 16) + 1			# encode ctr bytes string as hex string, convert to int, increment by 1
		ctr = format(ctr, 'x')							# format ctr as hex string
		ctr = fix_leading_zeroes(ctr,total_bytes)		# check if leading zeroes need to be added
		ctr = ctr.decode('hex')							# decode hex string back to bytes string
		plaintext_array[i] = xor(decryptor.update(ctr),msg[(i)*16:(i+1)*16])
		plaintext += plaintext_array[i]
	return plaintext

##################### CBC #####################
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
encryptor = cipher.encryptor()
cipher_text = encryptor.update(msg) + encryptor.finalize()
my_ciphertext = cbc_encrypt(key,iv,msg)

print "Real: " + cipher_text
print "Mine: " + my_ciphertext

decryptor = cipher.decryptor()
plain_text = decryptor.update(cipher_text) + decryptor.finalize()

print "Real: " + plain_text
print "Mine: " + cbc_decrypt(key,iv,my_ciphertext)

##################### CTR #####################
cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=default_backend())
encryptor = cipher.encryptor()
cipher_text = encryptor.update(msg) + encryptor.finalize()
my_ciphertext = ctr_encrypt(key,ctr,msg)

print "Real: " + cipher_text
print "Mine: " + my_ciphertext

decryptor = cipher.decryptor()
plain_text = decryptor.update(cipher_text) + decryptor.finalize()

print "Real: " + plain_text
print "Mine: " + ctr_decrypt(key,ctr,my_ciphertext)

#Cipher_Text_FROM_YOUR_CTR_IMPLEMENTATION = YOUR_CTR_IMPLEMENTATION(key, ctr, msg)

#assert cipher_text == Cipher_Text_FROM_YOUR_CTR_IMPLEMENTATION
