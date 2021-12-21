# Requirements: pycryptodome, numpy/scipy/matplotlib, pandas
import hashlib
import random 
import string
import binascii

# minning: for any string str, find nonce so hash(str+nonce)=hash starting with a number of leading ones
def hash(message): # turn string of any length into fixed length string of 64 hexidecimal chars
	return hashlib.sha256(message.encode('ascii')).hexdigest() # return message hash

def mine(message, difficulty=1):
	assert difficulty >= 1, "Mine Function Error: Difficulty Cannot be < 1 (0=Impossible)" 
	
	i = 0
	prefix = '1' * difficulty
	while True:
		nonce = str(i)
		digest = hash(message+nonce)
		if digest.startswith(prefix):
			#print('Found Nonce After %d Iterations' % i)
			#print(hash(message + str(nonce)))
			return nonce, i
		i += 1

'''
def main():	
	print("Calcluating Nonce for 'my secret message' with difficulty 1")
	nonce, iterations = mine('my secret message', difficulty=1)
	print('Found Nonce After %d Iterations' % iterations)
	print(hash(message + str(nonce)))
	print("Calcluating Nonce for 'my secret message' with difficulty 3")
	nonce, iterations = mine('my secret message', difficulty=3)
	print('Found Nonce After %d Iterations' % iterations)
	print(hash(message + str(nonce)))

if __name__ == "__main__":
	main()
'''