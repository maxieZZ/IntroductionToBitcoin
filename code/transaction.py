import string
import json
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from wallet import *
from mine import *

class Input(object): # transaction input which points to output of another transaction
	def __init__(self, transaction, output):
		self.transaction = transaction
		self.output = output
		assert 0 <= self.output < len(transaction.outputs), "Input Class Error: Cannot have more Outputs than Inputs"
	
	def to_dict(self):
		d = { # good way to store information
		'transaction': self.transaction.hash(),
		'output': self.output }
		return d

	@property
	def parent_output(self):
		return self.transaction.outputs[self.output]

class Output(object): # specifies amount and which wallet recieves it
	def __init__(self, reciever, amount):
		self.reciever = reciever
		self.amount = amount

	def to_dict(self):
		d = { 
		'reciever': self.reciever,
		'amount': self.amount }
		return d
		
def fee(inputs, outputs): # fee is the difference between input and output
	inputTotal = sum (i.transaction.outputs[i.output].amount for i in inputs)
	outputTotal = sum (o.amount for o in outputs)
	assert outputTotal <= inputTotal, "Fee Calculation Error: Output Greater than Input - Output=(%f) > Input=(%f)" % (outputTotal, inputTotal)
	diff = inputTotal-outputTotal
	return diff

class Transaction(object): # spend money a given wallet, inputs, and outputs
	def __init__(self, wallet, inputs, outputs):
		self.inputs = inputs
		self.outputs = outputs
		self.fee = fee(inputs,outputs)
		self.signature = wallet.sign(json.dumps(self.to_dict(include_signature=False)))
		
	def to_dict(self, include_signature=True):
		d = {
		"inputs": list(map(Input.to_dict,self.inputs)),
		"outputs": list(map(Output.to_dict,self.outputs)),
		"fee": self.fee
		}
		if include_signature:
			d["signature"] = self.signature
		return d
	
	def hash(self):
		return hash(json.dumps(self.to_dict()))

class firstTransaction(Transaction):
	# ie genesis: first transaction with no input and an output of 25
	def __init__(self, reciever, amount=25):
		self.inputs = []
		self.outputs = [Output(reciever, amount)]
		self.fee = 0
		self.signature = 'first'
	
	def to_dict(self, include_signature=False): 
		assert not include_signature, "First Transaction Creation Error: Signature Should NOT be Included"
		return super().to_dict(include_signature=False)
		
def balance(address, transactions): # computes wallet balance given list of transactions and an address
	balance = 0
	for t in transactions:
		for tin in t.inputs: # subtract all money sent out by adress
			if tin.parent_output.reciever == address:
				balance = balance - tin.parent_output.amount
		for out in t.outputs: # add all money recieved by address
			if out.reciever == address:
				balance = balance + out.amount	
	return balance

def verifyTransaction(transaction):
	# Verify a transaction is valid by making sure...
	# 1) Only the owner of the wallet is spending the money (ie all inputs must be owned by the owner)
	# 2) The owner cannot spend more money then they have in their wallet (checked by fee function)
	
	transaction_message = json.dumps(transaction.to_dict(include_signature=False))
	if isinstance(transaction, firstTransaction):
		# doesn't apply if this is the first transaction!
		return True

	# verify input transactions
	for tin in transaction.inputs:
		if not verifyTransaction(tin.transaction):
			print("VERIFY TRANSACTION ERROR: Not all Transaction Inputs are Valid")
			return False

	# 1) verify that only one wallet owns all input values
	first_input_address = transaction.inputs[0].parent_output.reciever
	for tin in transaction.inputs[1:]:
		if tin.parent_output.reciever != first_input_address:
			print("VERIFY TRANSACTION ERROR: Input Values are be Owned by Other Wallets")
			return False
	
	# Checking 2)
	if not verifySig(first_input_address, transaction_message, transaction.signature):
		print("VERIFY TRANSACTION ERROR: Invalid Transaction Signature")
		return False
	
	# call fee to trigger an assert if output sum is greater than input sum
	fee(transaction.inputs,transaction.outputs)
	return True

'''
def main():
	
	user1 = Wallet()
	user2 = Wallet()
	user3 = Wallet()
	
	# First Transaction: 25 coins to user1
	t1 = firstTransaction(user1.address)		
	# INVALID TRANSACTION: user2 tries to spend money from user1
	t12 = Transaction(user2, [Input(t1,0)], [Output(user3.address,10.0)])
	# user1 gives 5/25 to user2, 5/25 to user3, and keeps 15/25
	t2 = Transaction(user1,[Input(t1,0)], [Output(user2.address,5.0), Output(user1.address,15.0), Output(user3.address,5.0)])	
	# User3 gives 5/5 coins to user2
	t3 = Transaction(user3,[Input(t2,2)], [Output(user2.address,5.0)])	
	# User2 gives 8/10 coins to user3, and uses 1/10 as fee, leaving 1 remaining
	t4 = Transaction(user2, [Input(t2,0), Input(t3,0)], [Output(user3.address,8.0), Output(user2.address,1.0)])
	transactions = [t1,t2,t3,t4]
	
	print(verifyTransaction(t1))
	print(verifyTransaction(t12))
	print(verifyTransaction(t2))
	print(verifyTransaction(t3))
	print(verifyTransaction(t4))
	
	print("User 1 has %.02f coins" % balance(user1.address, transactions))
	print("User 2 has %.02f coins" % balance(user2.address, transactions))
	print("User 3 has %.02f coins" % balance(user3.address, transactions))


if __name__ == "__main__":
	main()
'''