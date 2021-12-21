import hashlib
import random 
import string
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

class Wallet(object): # ie private public key pair
	def __init__(self):
		random_num = Crypto.Random.new().read # random values for private and public keys
		self._private = RSA.generate(1024, random_num) # generate random private key
		self._public = 	self._private.publickey() # convert private to public
		self._signer = PKCS1_v1_5.new(self._private) # returns object to perform signature
	
	@property
	def address(self): # address here is just public key
		return binascii.hexlify(self._public.exportKey(format='DER')).decode('ascii')
	
	def sign(self, message): # sign a given message using personal signer
		hash_val = SHA.new(message.encode('utf8')) # hash/encrypt message before signing
		return binascii.hexlify(self._signer.sign(hash_val)).decode('ascii')
	
def verifySig(address, message, sig):
	#print("address is %s" + str(address) + "message is %s" + str(message), "sig is %s" + str(sig))
	pubkey = RSA.importKey(binascii.unhexlify(address)) # import address as public key
	verification = PKCS1_v1_5.new(pubkey) # to compare with signer attribute
	hash_val = SHA.new(message.encode('utf8')) # hash message same way as before
	return verification.verify(hash_val, binascii.unhexlify(sig))
'''
def main():	
	myWallet = Wallet()
	sig = myWallet.sign('mysignature')
	print("New Wallet created and signed with message 'mysignature'")
	isVerified = verifySig(myWallet.address,'mysignature', sig)
	if (isVerified==True):
		print("Verified signature with 'mysignature'")
	isVerified = verifySig(myWallet.address,'not my signature', sig)
	if (isVerified!=True):
		print("Could not verify 'not my signature'")

if __name__ == "__main__":
	main()
'''
	