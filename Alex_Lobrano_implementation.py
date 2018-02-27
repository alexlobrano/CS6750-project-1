import os
import sys
import time
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

def fix_leading_zeros(ctr):
	add_zero = 32 - len(ctr)
	for i in range(add_zero):
		ctr = "0" + ctr
	return ctr
	
def generate_message(size):
	temp = ''
	for i in range(size):
		temp += random.choice(string.ascii_letters + string.digits)
	return temp

def increment_byte(val):
	temp = val + 1
	temp = temp % 256
	return temp
	
def change_byte(first_byte,pad_byte,value):
	temp = first_byte ^ pad_byte
	return temp ^ value
	
def create_string(array):
	temp_string = ""
	for i in range(len(array)):
		temp_string += str(chr(array[i]))
	return temp_string
	
def cbc_encrypt(key, iv, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	encryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	cipher_array = [None] * total_bytes
	
	# Byte 1
	cipher_array[0] = encryptor.update(xor(iv,msg[0:16]))
	ciphertext = cipher_array[0]
	
	# Rest of bytes
	for i in range(1,total_bytes):
		cipher_array[i] = encryptor.update(xor(cipher_array[i-1],msg[i*16:(i+1)*16]))
		ciphertext += cipher_array[i]
	return ciphertext
	
def cbc_decrypt(key, iv, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	decryptor = cipher.decryptor()
	
	total_bytes = (len(msg)/16)
	plaintext_array = [None] * total_bytes
	
	# Byte 1
	plaintext_array[0] = xor(decryptor.update(msg[0:16]),iv)
	plaintext = plaintext_array[0]
	
	# Rest of bytes
	for i in range(1,total_bytes):
		plaintext_array[i] = xor(decryptor.update(msg[(i)*16:(i+1)*16]),msg[(i-1)*16:i*16])
		plaintext += plaintext_array[i]
	return plaintext	
	
def ctr_encrypt(key, ctr, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	encryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	cipher_array = [None] * total_bytes
	
	# Byte 1
	cipher_array[0] = xor(msg[0:16],encryptor.update(ctr))
	ciphertext = cipher_array[0]

	# Rest of bytes
	for i in range(1,total_bytes):
		ctr = int(ctr.encode('hex'), 16) + 1			# Encode ctr bytes string as hex string, convert to int, increment by 1
		ctr = format(ctr, 'x')							# Format ctr as hex string
		ctr = fix_leading_zeros(ctr)					# Check if leading zeros need to be added
		ctr = ctr.decode('hex')							# Decode hex string back to bytes string
		cipher_array[i] = xor(msg[i*16:(i+1)*16],encryptor.update(ctr))
		ciphertext += cipher_array[i]
	return ciphertext
	
def ctr_decrypt(key, ctr, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	decryptor = cipher.encryptor()
	
	total_bytes = (len(msg)/16)
	plaintext_array = [None] * total_bytes
	
	# Byte 1
	plaintext_array[0] = xor(decryptor.update(ctr),msg[0:16])
	plaintext = plaintext_array[0]

	# Rest of bytes
	for i in range(1,total_bytes):
		ctr = int(ctr.encode('hex'), 16) + 1			# Encode ctr bytes string as hex string, convert to int, increment by 1
		ctr = format(ctr, 'x')							# Format ctr as hex string
		ctr = fix_leading_zeros(ctr)					# Check if leading zeros need to be added
		ctr = ctr.decode('hex')							# Decode hex string back to bytes string
		plaintext_array[i] = xor(msg[(i)*16:(i+1)*16],decryptor.update(ctr))
		plaintext += plaintext_array[i]
	return plaintext
	
def padding_oracle(key, iv, ciphertext):
	plaintext = cbc_decrypt(key, iv, ciphertext)
	plaintext_array = bytearray(plaintext)
	pad_bytes = plaintext_array[len(plaintext_array)-1]
	if(pad_bytes == 0): return 0	#if last byte is 0, invalid pad
	for i in range(pad_bytes):
		if(plaintext_array[len(plaintext_array)-1-i] != pad_bytes): 
			print "Invalid padding"
			return 0
	print "Valid padding"
	return 1
	
def oracle_attack_last_block_recovery(key, iv, ciphertext):	
	filename1 = time.strftime("%Y%m%d-%H%M%S")
	sys.stdout = open(filename1 + '.txt', 'w')
	print "Library encryption: " + ciphertext.encode('hex')
	total_queries = 0
	original_cipher_array = bytearray(ciphertext)
	original_iv_array = bytearray(iv)
	test_cipher_array = bytearray(ciphertext)
	test_cipher_array[0] = increment_byte(test_cipher_array[0])
	print "Changing byte 0 from", format(original_cipher_array[0], 'x'), "to", format(test_cipher_array[0], 'x')
	new_ciphertext = create_string(test_cipher_array)
	print "Querying oracle with", new_ciphertext.encode('hex')
	i = 0
	total_queries += 1

	# Find how many bytes of padding there are
	while(padding_oracle(key,iv,new_ciphertext)):
		i += 1 
		test_cipher_array[i-1] = original_cipher_array[i-1]
		test_cipher_array[i] = increment_byte(test_cipher_array[i])
		print "Changing byte", i, "of ciphertext from", format(original_cipher_array[i], 'x'), "to", format(test_cipher_array[i], 'x')
		new_ciphertext = create_string(test_cipher_array)
		print "Querying oracle with", new_ciphertext.encode('hex')
		total_queries += 1

	# Once here, i is equal to the byte which modifies the first byte of the padding
	padding_bytes = (len(test_cipher_array) - i) % 16
	first_pad_byte = i
	print "Bytes of padding:", padding_bytes
	print "Byte to use to modify first byte of padding:", first_pad_byte
	test_cipher_array = bytearray(ciphertext)
	recovered_msg = [None] * (16-padding_bytes)

	# Execute this loop equal to the number of bytes in the last block which aren't padding (to recover them)
	for x in range(16-padding_bytes):
		
		# Update the value of bytes determined to be padding to 1 higher than the number of pad bytes
		for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
			prev_val = format(test_cipher_array[k], 'x')
			test_cipher_array[k] = change_byte(test_cipher_array[k],padding_bytes+x,padding_bytes+x+1)
			print "Changing byte", k, "of ciphertext from", prev_val, "to", format(test_cipher_array[k], 'x')
		
		# Create new ciphertext string with the modified pad bytes
		new_ciphertext = create_string(test_cipher_array)
		
		print "Querying oracle with", new_ciphertext.encode('hex')
		total_queries += 1
		prev_val = format(test_cipher_array[first_pad_byte-x-1], 'x')
		
		# Loop until the oracle reveals the padding is valid
		while(not padding_oracle(key,iv,new_ciphertext)):
		
			# Increment the byte right before the pad
			test_cipher_array[first_pad_byte-x-1] = increment_byte(test_cipher_array[first_pad_byte-x-1])
			print "Changing byte", first_pad_byte-x-1, "of ciphertext from", prev_val, "to", format(test_cipher_array[first_pad_byte-x-1], 'x')
			prev_val = format(test_cipher_array[first_pad_byte-x-1], 'x')
			
			# Create new ciphertext string with the modified bytes
			new_ciphertext = create_string(test_cipher_array)
			print "Querying oracle with", new_ciphertext.encode('hex')
			total_queries += 1
			
		# Once here, the value of index [first_pad_byte-x-1] in test_cipher_array gives you a valid pad with the existing pad bytes
		# Recover it by x-oring with the new pad number, then x-oring with the original unmodified ciphertext block at index [first_pad_byte-x-1]
		temp = test_cipher_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
		plain_byte = temp ^ original_cipher_array[first_pad_byte-x-1]
		
		# Save the recovered byte
		recovered_msg[16-padding_bytes-x-1] = plain_byte
		print "Saving",chr(plain_byte),"to index",16-padding_bytes-x-1
	
	# Print the recovered message
	recovered_text = create_string(recovered_msg)
	print "Recovered message:", recovered_text
	print "Total queries:", total_queries
	
def oracle_attack_full_recovery(key, iv, ciphertext):
	filename1 = time.strftime("%Y%m%d-%H%M%S")
	sys.stdout = open(filename1 + '.txt', 'w')
	print "Library encryption: " + ciphertext.encode('hex')
	total_queries = 0
	original_cipher_array = bytearray(ciphertext)
	original_iv_array = bytearray(iv)
	test_cipher_array = bytearray(ciphertext)
	test_cipher_array[0] = increment_byte(test_cipher_array[0])
	print "Changing byte 0 from", format(original_cipher_array[0], 'x'), "to", format(test_cipher_array[0], 'x')
	new_ciphertext = create_string(test_cipher_array)
	print "Querying oracle with", new_ciphertext.encode('hex')
	i = 0
	total_queries += 1

	# Find how many bytes of padding there are
	while(padding_oracle(key,iv,new_ciphertext)):
		i += 1 
		test_cipher_array[i-1] = original_cipher_array[i-1]
		test_cipher_array[i] = increment_byte(test_cipher_array[i])
		print "Changing byte", i, "of ciphertext from", format(original_cipher_array[i], 'x'), "to", format(test_cipher_array[i], 'x')
		new_ciphertext = create_string(test_cipher_array)
		print "Querying oracle with", new_ciphertext.encode('hex')
		total_queries += 1

	# Once here, i is equal to the byte which modifies the first byte of the padding
	padding_bytes = (len(test_cipher_array) - i) % 16
	first_pad_byte = i
	print "Bytes of padding:", padding_bytes
	print "Byte to use to modify first byte of padding:", first_pad_byte
	test_cipher_array = bytearray(ciphertext)
	recovered_msg = [None] * (len(ciphertext)-padding_bytes)

	# Execute this loop equal to the number of bytes in the last block which aren't padding (to recover them)
	for x in range(16-padding_bytes):
		
		# Update the value of bytes determined to be padding to 1 higher than the number of pad bytes
		for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
			prev_val = format(test_cipher_array[k], 'x')
			test_cipher_array[k] = change_byte(test_cipher_array[k],padding_bytes+x,padding_bytes+x+1)
			print "Changing byte", k, "of ciphertext from", prev_val, "to", format(test_cipher_array[k], 'x')
		
		# Create new ciphertext string with the modified pad bytes
		new_ciphertext = create_string(test_cipher_array)
		
		print "Querying oracle with", new_ciphertext.encode('hex')
		total_queries += 1
		prev_val = format(test_cipher_array[first_pad_byte-x-1], 'x')
		
		# Loop until the oracle reveals the padding is valid
		while(not padding_oracle(key,iv,new_ciphertext)):
		
			# Increment the byte right before the pad
			test_cipher_array[first_pad_byte-x-1] = increment_byte(test_cipher_array[first_pad_byte-x-1])
			print "Changing byte", first_pad_byte-x-1, "of ciphertext from", prev_val, "to", format(test_cipher_array[first_pad_byte-x-1], 'x')
			prev_val = format(test_cipher_array[first_pad_byte-x-1], 'x')
			
			# Create new ciphertext string with the modified bytes
			new_ciphertext = create_string(test_cipher_array)
			print "Querying oracle with", new_ciphertext.encode('hex')
			total_queries += 1
			
		# Once here, the value of index [first_pad_byte-x-1] in test_cipher_array gives you a valid pad with the existing pad bytes
		# Recover it by x-oring with the new pad number, then x-oring with the original unmodified ciphertext block at index [first_pad_byte-x-1]
		temp = test_cipher_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
		plain_byte = temp ^ original_cipher_array[first_pad_byte-x-1]
		
		# Save the recovered byte
		recovered_msg[len(ciphertext)-padding_bytes-x-1] = plain_byte
		print "Saving",chr(plain_byte),"to index",len(ciphertext)-padding_bytes-x-1
		
	# To recover more blocks, make a new ciphertext of length new_length which will exclude the last block recovered
	new_length = len(test_cipher_array) - 16

	# This loop recovers all blocks prior to the last block (except the first one)
	while(new_length > 16):

		# Create new ciphertext without the last recovered block
		test_cipher_array = bytearray(ciphertext[:new_length])
		new_ciphertext = create_string(test_cipher_array)
		print "Querying oracle with ", new_ciphertext.encode('hex')
		total_queries += 1
		prev_val = format(test_cipher_array[first_pad_byte], 'x')

		# Set first_pad_byte equal to the byte which modifies the first byte of the padding, which is the last byte of the second to last block
		first_pad_byte = new_length - 16 - 1

		# Find how to make the decrypted last byte of this ciphertext equal to 1, which is when the oracle will reveal the padding is valid	
		while(not padding_oracle(key, iv, new_ciphertext)):
		
			# Increment the first_pad_byte byte, which is the last byte of the second to last block
			test_cipher_array[first_pad_byte] = increment_byte(test_cipher_array[first_pad_byte])
			print "Changing byte", first_pad_byte, "of ciphertext from", prev_val, "to", format(test_cipher_array[first_pad_byte], 'x')
			prev_val = format(test_cipher_array[first_pad_byte], 'x')
			
			# Create new ciphertext string with modified bytes
			new_ciphertext = create_string(test_cipher_array)
			print "Querying oracle with ", new_ciphertext.encode('hex')
			total_queries += 1
			
		# Once here, we can recover the last byte of this block and begin adding more padding
		# Recover it by x-oring with the new pad number, then x-oring with the original unmodified ciphertext block at index [first_pad_byte]
		padding_bytes = 1
		temp = test_cipher_array[first_pad_byte] ^ padding_bytes
		plain_byte = temp ^ original_cipher_array[first_pad_byte]
		
		# Save the recovered byte
		recovered_msg[new_length-1] = plain_byte
		print "Saving",chr(plain_byte),"to index",new_length-1

		# Loop to recover the other 15 bytes of this block
		for x in range(0, 15):
		
			# Update the value of bytes determined to be padding to 1 higher than the number of pad bytes
			for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
				prev_val = format(test_cipher_array[k], 'x')
				test_cipher_array[k] = change_byte(test_cipher_array[k],padding_bytes+x,padding_bytes+x+1)
				print "Changing byte", k, "of ciphertext from", prev_val, "to", format(test_cipher_array[k], 'x')
			
			# Create new ciphertext string with the modified pad bytes
			new_ciphertext = create_string(test_cipher_array)
			
			print "Querying oracle with", new_ciphertext.encode('hex')
			total_queries += 1
			prev_val = format(test_cipher_array[first_pad_byte-x-1], 'x')
			
			# Loop until the oracle reveals the padding is valid
			while(not padding_oracle(key,iv,new_ciphertext)):
				test_cipher_array[first_pad_byte-x-1] = increment_byte(test_cipher_array[first_pad_byte-x-1])
				print "Changing byte", first_pad_byte-x-1, "of ciphertext from", prev_val, "to", format(test_cipher_array[first_pad_byte-x-1], 'x')
				prev_val = format(test_cipher_array[first_pad_byte-x-1], 'x')
				
				# Create new ciphertext string with the modified bytes
				new_ciphertext = create_string(test_cipher_array)
				print "Querying oracle with", new_ciphertext.encode('hex')
				total_queries += 1
				
			# Once here, the value of index [first_pad_byte-x-1] in test_cipher_array gives you a valid pad with the existing pad bytes
			# Recover it by x-oring with the new pad number, then x-oring with the original unmodified ciphertext block at index [first_pad_byte-x-1]
			temp = test_cipher_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
			plain_byte = temp ^ original_cipher_array[first_pad_byte-x-1]

			# Save the recovered byte
			recovered_msg[new_length-x-2] = plain_byte
			print "Saving",chr(plain_byte),"to index",new_length-x-2
			
		# Make a new ciphertext of length new_length which will exclude the last block recovered
		new_length = len(test_cipher_array) - 16
			
	# Recover the first block 
	# Create new ciphertext without the last recovered block
	test_cipher_array = bytearray(ciphertext[:new_length])
	new_ciphertext = create_string(test_cipher_array)

	# Create new IV after modifying last byte of IV
	test_iv_array = bytearray(iv)
	test_iv_array[len(test_iv_array)-1] = increment_byte(test_iv_array[len(test_iv_array)-1])
	new_iv = create_string(test_iv_array)

	# Set first_pad_byte equal to the byte which modifies the first byte of the padding, which is the last byte of the IV
	first_pad_byte = new_length - 1

	print "Querying oracle with", new_ciphertext.encode('hex'),"and IV",new_iv.encode('hex')
	total_queries += 1
	prev_val = format(test_iv_array[first_pad_byte], 'x')

	# Find how to make the decrypted last byte of this ciphertext equal to 1, which is when the oracle will reveal the padding is valid	
	while(not padding_oracle(key, new_iv, new_ciphertext)):

		# Increment the first_pad_byte byte of the IV, which is the last byte
		test_iv_array[first_pad_byte] = increment_byte(test_iv_array[first_pad_byte])
		print "Changing byte", first_pad_byte, "of IV from", prev_val, "to", format(test_iv_array[first_pad_byte], 'x')
		prev_val = format(test_iv_array[first_pad_byte], 'x')
		
		# Create new IV string with modified bytes
		new_iv = create_string(test_iv_array)
		print "Querying oracle with", new_ciphertext.encode('hex'),"and IV",new_iv.encode('hex')
		total_queries += 1
		
	# Once here, we can recover the last byte of this block and begin adding more padding
	# Recover it by x-oring with the new pad number, then x-oring with the original unmodified IV byte at index [first_pad_byte]
	padding_bytes = 1
	temp = test_iv_array[first_pad_byte] ^ padding_bytes
	plain_byte = temp ^ original_iv_array[first_pad_byte]

	# Save the recovered byte
	recovered_msg[new_length-1] = plain_byte
	print "Saving",chr(plain_byte),"to index",new_length-1

	# Loop to recover the other 15 bytes of this block
	for x in range(0, 15):

		# Update the value of bytes determined to be padding to 1 higher than the number of pad bytes
		for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
			prev_val = format(test_iv_array[k], 'x')
			test_iv_array[k] = change_byte(test_iv_array[k],padding_bytes+x,padding_bytes+x+1)
			print "Changing byte", k, "of IV from", prev_val, "to", format(test_iv_array[k], 'x')
			
		# Create new IV string with the modified pad bytes
		new_iv = create_string(test_iv_array)
		
		print "Querying oracle with", new_ciphertext.encode('hex'),"and IV",new_iv.encode('hex')
		total_queries += 1
		prev_val = format(test_iv_array[first_pad_byte-x-1], 'x')
		
		# Loop until the oracle reveals the padding is valid
		while(not padding_oracle(key, new_iv, new_ciphertext)):
			test_iv_array[first_pad_byte-x-1] = increment_byte(test_iv_array[first_pad_byte-x-1])
			print "Changing byte", k, "of IV from", prev_val, "to", format(test_iv_array[first_pad_byte-x-1], 'x')
			prev_val = format(test_iv_array[first_pad_byte-x-1], 'x')
			
			# Create new IV string with the modified pad bytes
			new_iv = create_string(test_iv_array)
			print "Querying oracle with", new_ciphertext.encode('hex'),"and IV",new_iv.encode('hex')
			total_queries += 1
			
		# Once here, the value of index [first_pad_byte-x-1] in test_iv_array gives you a valid pad with the existing pad bytes
		# Recover it by x-oring with the new pad number, then x-oring with the original unmodified IV byte at index [first_pad_byte-x-1]
		temp = test_iv_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
		plain_byte = temp ^ original_iv_array[first_pad_byte-x-1]

		# Save the recovered byte
		recovered_msg[new_length-x-2] = plain_byte
		print "Saving",chr(plain_byte),"to index",new_length-x-2
			
	# Print the recovered message
	recovered_text = create_string(recovered_msg)
	print "Recovered message:", recovered_text
	print "Total queries:", total_queries