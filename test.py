from Alex_Lobrano_implementation import *
	
key = os.urandom(16)
iv = os.urandom(16)
ctr = os.urandom(16)
#msg = "This is a test of a padding oracle attack."
msg = "This is a test of a padding oracle attack. Testing with a second message."
backend = default_backend() 

##################### CBC #####################

filename1 = time.strftime("%Y%m%d-%H%M%S")
sys.stdout = open(filename1 + '.txt', 'w')

print "Message:", msg

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msg) + encryptor.finalize()

print "CBC:"
print "Library encryption: " + ciphertext.encode('hex')

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print "Library decryption: " + plaintext.encode('hex')

#attack starts here

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
for x in range(0, 16 - padding_bytes):
	
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
		
# Print the entire recovered message
recovered_text = create_string(recovered_msg)
print "Recovered message:", recovered_text
print "Total queries:", total_queries
