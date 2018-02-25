import os
import sys
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherAlgorithm
from cryptography.hazmat.backends import default_backend 

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

def fix_leading_zeroes(ctr):
	add_zero = 32 - len(ctr)
	for i in range(add_zero):
		ctr = "0" + ctr
	return ctr
	
def generate_message(size):
	temp = ''
	for i in range(size):
		temp += random.choice(string.ascii_letters + string.digits)
	return temp
	
def cbc_encrypt(key, iv, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	encryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	cipher_array = [None] * total_bytes
	
	#byte 1
	cipher_array[0] = encryptor.update(xor(iv,msg[0:16]))
	ciphertext = cipher_array[0]
	
	#rest of bytes
	for i in range(1,total_bytes):
		cipher_array[i] = encryptor.update(xor(cipher_array[i-1],msg[i*16:(i+1)*16]))
		ciphertext += cipher_array[i]
	return ciphertext
	
def cbc_decrypt(key, iv, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
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
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	encryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	cipher_array = [None] * total_bytes
	
	#byte 1
	cipher_array[0] = xor(msg[0:16],encryptor.update(ctr))
	ciphertext = cipher_array[0]

	#rest of bytes
	for i in range(1,total_bytes):
		ctr = int(ctr.encode('hex'), 16) + 1			# encode ctr bytes string as hex string, convert to int, increment by 1
		ctr = format(ctr, 'x')							# format ctr as hex string
		ctr = fix_leading_zeroes(ctr)		# check if leading zeroes need to be added
		ctr = ctr.decode('hex')							# decode hex string back to bytes string
		cipher_array[i] = xor(msg[i*16:(i+1)*16],encryptor.update(ctr))
		ciphertext += cipher_array[i]
	return ciphertext
	
def ctr_decrypt(key, ctr, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
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
		ctr = fix_leading_zeroes(ctr)		# check if leading zeroes need to be added
		ctr = ctr.decode('hex')							# decode hex string back to bytes string
		plaintext_array[i] = xor(msg[(i)*16:(i+1)*16],decryptor.update(ctr))
		plaintext += plaintext_array[i]
	return plaintext
	
def padding_oracle(key, iv, ciphertext):
	plaintext = cbc_decrypt(key, iv, ciphertext)
	plaintext_array = bytearray(plaintext)
	pad_bytes = plaintext_array[len(plaintext_array)-1]
	for i in range(pad_bytes):
		if(plaintext_array[len(plaintext_array)-1-i] != pad_bytes): 
			print "Invalid padding"
			return 0
	print "Valid padding"
	return 1
	
def oracle_attack(key, iv, ciphertext):
	cipher_array = bytearray(ciphertext)
	cipher_array[0] += 1
	new_ciphertext = ""
	for i in range(len(cipher_array)):
		new_ciphertext += str(chr(cipher_array[i]))