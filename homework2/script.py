from Crypto.Cipher import DES
import string
import time

start_time = time.time()
print "Start time : ", start_time

cipher_text = "\xc5\x81\x97~\xb4\x0b:U\x13^\x9c\xb2:\xedcC\xe5\n\xab\xb2\xbas\xbe/\r\xa8\x00'\x87\x91Ch\xb8\x060\xfb\xf8V\xf7)\x1d\xfb\x12\xe7\x16\xf0\x12\x1dQ\x99Gs`\xf5qZjQL\xe1\x1f\xfd\x90E"
count = 0

for key_root in xrange(0, 100000000):
	key = ""
	n = key_root
	while(n > 0):
		key = str(n%10) + key
		n = n/10 
	if (len(key) < 8):
		for key_root in xrange(len(key), 8):
			key = '0' + key
	des = DES.new(key, DES.MODE_ECB)
	decrypted_text = des.decrypt(cipher_text)
	if all(c in string.printable for c in decrypted_text):
		print key,decrypted_text
		count += 1

print "Number of keys : ", count
end_time = time.time()
print "End time : ", end_time
print "Total time taken in decryption (in sec) : ", end_time-start_time
