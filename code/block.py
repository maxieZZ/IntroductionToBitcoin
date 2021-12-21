import sys
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
from transaction import *

INCENTIVE = 25 # Number of coins miners get for mining a block
DIFFICULTY = 2

def computeTotalFee(transactions): # return total fee for a set of transactions
	total = sum(t.fee for t in transactions)
	return total
class Block(object):
	def to_dict(self, include_hash=True):
		if include_hash==True:				
			d = {
				"transactions": list(map(Transaction.to_dict, self.transactions)),
				"parentBlock": self.parent.hash,
				"nonce": self.nonce,
				"hash": self.hash
			}
		else: 
			d = {
				"transactions": list(map(Transaction.to_dict, self.transactions)),
				"parentBlock": self.parent.hash,
			}
		return d
		 
	def __init__(self, transactions, parent, minerAddress, skipVer=False):
		# transactions=list of transactions to include in block
		# parent=previous block
		# minerAddress=address of miners wallet (where incentive and fees are deposited)
		reward = computeTotalFee(transactions) + INCENTIVE # add incentive to total fees
		self.transactions = [firstTransaction(minerAddress,amount=reward)] + transactions # add first transaction to list of trans
		self.parent = parent
		
		if not skipVer: # verify each transaction
			assert all(map(verifyTransaction, transactions)), "Block Creation Error: One or more Transactions are Invalid"
		block = json.dumps(self.to_dict(include_hash=False))
		self.nonce, _ = mine(block, DIFFICULTY) 
		self.hash = hash(block + self.nonce) # hash block and nonce
			
	def transactionFee(self): # return the transaction fee for the block
		return computeTotalFee(self.transactions)


class firstBlock(Block):
	def __init__(self, minerAddress):
		super(firstBlock, self).__init__(transactions=[], parent=None, minerAddress=minerAddress)
	
	def transactionFee(self): # return the transaction fee for the block
		return computeTotalFee(self.transactions)
		
	def to_dict(self, include_hash=True):
		d = {
		"transactions": [],
		"firstBlock": True,
		}
		if include_hash:
			d["nonce"] = self.nonce
			d["hash"] = self.hash
		return d
	
def verifyBlock(block, firstBlock, outputs=None):
	# Checks if a given block is valid by...
	# 1) Hash starts with required number of 1s
	# 2) Same transaction output is NOT used more than once
	# 3) All transactions must be valid
	# 4) First transaction in block must be genesis with INCENTIVE+totalFee
	# Arguments: block=block to validate, first block=genesis block, 
	# outputs=list of outputs used in transactions for all blocks above this one
	
	if outputs is None:
		outputs = set()
	
	prefix = '1' * DIFFICULTY
	if not block.hash.startswith(prefix): # check #1
		print("BLOCK VERIFICATION ERROR: Block Hash Starts with Incorrect Prefix")
		return False

	if not all(map(verifyTransaction,block.transactions)): # check verification
		print("BLOCK VERIFICATION ERROR: Not all Transactions are Valid")
		return False
	
	for transaction in block.transactions:
		for i in transaction.inputs:
			if i.parent_output in outputs:
				print("BLOCK VERIFICATION ERROR: Transaction Outputs have already been Spent")
				return False
			outputs.add(i.parent_output)
			
	if not (block.hash == firstBlock.hash): # verify all previous blocks up to first block
		if not verifyBlock(block.parent,firstBlock, outputs):
			print("BLOCK VERIFICATION ERROR: Another Block in the Chain is Invalid")
			return False
	
	# verify first transaction is miners reward
	trans0 = block.transactions[0]
	if not isinstance(trans0, firstTransaction):
		print("BLOCK VERIFICATION ERROR: First Transaction Block is not Identifiable as Genesis")
		return False
	
	if not len(trans0.outputs)==1:
		print("BLOCK VERIFICATION ERROR: First Transaction can only have One Ouput")
		return False
		
	reward = computeTotalFee(block.transactions[1:]) + INCENTIVE
	
	if not trans0.outputs[0].amount == reward:
		logging.error("BLOCK VERIFICATION ERROR: First Transaction does NOT have Correct Reward Value")
		return False
	
	for i, trans in enumerate(block.transactions):
		if i == 0:
			if not isinstance(trans, firstTransaction):
				print("BLOCK VERIFICATION ERROR: First Transaction (idx=0) is not Identifiable as Genesis")
				return False
		
		elif isinstance(trans, firstTransaction):
			print("BLOCK VERIFICATION ERROR: Blocks after First Block are Identified as the Genesis")
			return False
	
	return True 

def getTransactions(block, firstBlock): # get transactions of all blocks
	transactions = [] + block.transactions
	if block.hash != firstBlock.hash:
		transactions += getTransactions(block.parent, firstBlock)
	return transactions

def chainLength(block): # Get total length of the block chain
	if block.parent is None:
		return 1
	else:
		return 1 + chainLength(block.parent)
	
def main():	
	go=1
	while (go==1):
		print("BASIC BLOCKCHAIN IMPLEMENTATION\n")
		print("This program illustrates several classes and functions meant to mimic the behavoir of a working blockchain, specific functionalities are listed as menu items below.\n")
		print("(1) Look at differences between mining difficulty levels and calculate nonce value\n" )
		print("(2) Create a wallet and test verification for valid and invalid signature\n")
		print("(3) Execute a series of transactions with three different user wallets\n")
		print("(4) Create a series of block transactions and check validations for various types of attacks\n")
	
		menuNum = int(input("Please Enter a Menu Item Number from Above\n"))
	
		if(menuNum==1):
			print("\nOPTION 1: Calucating nonces for 'my secret message' with varying levels of difficulty\n")
			print("Calcluating Nonce for 'my secret message' with difficulty 1")
			message = 'my secret message'
			nonce, iterations = mine(message, difficulty=1)
			print('Found Nonce After %d Iterations' % iterations)
			print(hash(message + str(nonce)))
			print("Calcluating Nonce for 'my secret message' with difficulty 3")
			nonce, iterations = mine(message, difficulty=3)
			print('Found Nonce After %d Iterations' % iterations)
			print(hash(message + str(nonce)))
			go = int(input("\nPlease Enter 1 to return to Main Menu Options and 0 to Quit\n"))
		
		if(menuNum==2):
			print("\nOPTION 2: Creating and verifying a wallet with a valid and invalid signature\n")
			myWallet = Wallet()
			sig = myWallet.sign('mysignature')
			print("New Wallet created and signed with message 'mysignature'")
			isVerified = verifySig(myWallet.address,'mysignature', sig)
			if (isVerified==True):
				print("Verified signature with 'mysignature'")
			isVerified = verifySig(myWallet.address,'notmysignature', sig)
			if (isVerified!=True):
				print("Could not verify 'notmysignature'")
			go = int(input("\nPlease Enter 1 to return to Main Menu Options and 0 to Quit\n"))
		
		if(menuNum==3):
			print("\nOPTION 3: Executing a series of transactions with three different user wallets\n")
			user1 = Wallet()
			user2 = Wallet()
			user3 = Wallet()

			print("First Transaction: 25 coins to user1\n")
			t1 = firstTransaction(user1.address)	
			print(verifyTransaction(t1))	
			print("User 2 will now try to spend money from user1\n")
			t12 = Transaction(user2, [Input(t1,0)], [Output(user3.address,10.0)])
			print(verifyTransaction(t12))
			print("User 1 gives 5/25 to User 2, 5/25 to User 3, and keeps 15/25\n")
			t2 = Transaction(user1,[Input(t1,0)], [Output(user2.address,5.0), Output(user1.address,15.0), Output(user3.address,5.0)])	
			print(verifyTransaction(t2))
			print("User 3 gives 5/5 coins to User 2\n")
			t3 = Transaction(user3,[Input(t2,2)], [Output(user2.address,5.0)])	
			print(verifyTransaction(t3))
			print("User 2 gives 8/10 coins to User 3, and uses 1/10 as fee, leaving 1 remaining\n")
			t4 = Transaction(user2, [Input(t2,0), Input(t3,0)], [Output(user3.address,8.0), Output(user2.address,1.0)])
			transactions = [t1,t2,t3,t4]
			print(verifyTransaction(t4))

			print("User 1 has %.02f coins" % balance(user1.address, transactions))
			print("User 2 has %.02f coins" % balance(user2.address, transactions))
			print("User 3 has %.02f coins" % balance(user3.address, transactions))
			go = int(input("\nPlease Enter 1 to return to Main Menu Options and 0 to Quit\n"))

		if(menuNum==4):
			user1 = Wallet()
			user2 = Wallet()
			user3 = Wallet()
			print("\nOPTION 4: Creating first block with 25 coins to user 1\n")
			startB = firstBlock(minerAddress=user1.address)
			print("MAIN: First Block Hash: " + startB.hash + "with Fee: " + str(startB.transactionFee()))
	
			t1 = startB.transactions[0]
			print("transaction 2: 25 coins are mined by user1 - 5 given to user2, 5 to user3, and 15 back to user1\n")
			# user1=15, user2=5, user3=5
			t2 = Transaction(user1, [Input(t1,0)], [Output(user2.address,5.0), Output(user1.address,15.0), Output(user3.address, 5.0)])
		
			print("transaction 3: user3 gives 5 to user2 leaving them with 0 and user2 with 10\n")
			# user1=15, user2=10, user3=0
			t3 = Transaction(user3,[Input(t2,2)], [Output(user2.address,5.0)])	

			print("transaction 4: user2 gives 8 to user3, and uses 1 for a fee\n")  
			# user1=15, user2=1, user3=8
			t4 = Transaction(user2, [Input(t2,0), Input(t3,0)], [Output(user3.address,8.0), Output(user2.address,1.0)])
	
			print("user3 mines 2 blocks which now gives him (2*25)+8+1=59\n")
	
			print("creating next block in chain (stores transaction2)\n")
			block1 = Block([t2], parent=startB, minerAddress=user3.address)
			print("MAIN: Block 1: " + block1.hash + "with Fee: " + str(block1.transactionFee()))
	
			print("block 2 stores transactions 3 and 4\n")
			block2 = Block([t3,t4], parent=block1, minerAddress=user3.address)
			print("MAIN: Block 2: " + block2.hash + "Fee: " + str(block2.transactionFee()))
	
			print("MAIN: Block verification until block1 is " + str(verifyBlock(block1, startB)))
			print("MAIN: Block verification until block2 is " + str(verifyBlock(block2, startB)))

			transactions = getTransactions(block2, startB)
	
			print("MAIN: User 1 Balance: %.02f" % balance(user1.address, transactions))
			print("MAIN: User 2 Balance: %.02f" % balance(user2.address, transactions))
			print("MAIN: User 3 Balance: %.02f" % balance(user3.address, transactions))	
			print()
	
			# Attack 1: Spend another users money
			# Situation: User 3 spends the money of User 2:
			print("Verifying a block where user3 attempts to spend user2's money...")
			t5 = Transaction(user3,[Input(t4,1)],[Output(user3.address,1.0)])
			block3 = Block([t5],parent=block2,minerAddress=user3.address,skipVer=True)
			verifyBlock(block3,startB)
			print()

			# Attack 2: Modify a transaction that is already included in the block
			print("Verifying a block that has been modified (4 is added to the amount after creation)...")
			t6 = Transaction(user2,[Input(t2,0), Input(t3,0)],[Output(user3.address,8),Output(user2.address,1.0)])	
			t6.outputs[0].amount+=4 # here is where the block gets maliciously modified
			block4 = Block([t3,t6], parent=block1, minerAddress=user3.address,skipVer=True)
			verifyBlock(block4,startB)
			print()
	
			# Attack 3: Double spending (ie duplicating a signed transaction)
			print("Verifying a block that has duplicated a transaction (double spending)...")
			block5 = Block([t3,t3,t4], parent=block1, minerAddress=user2.address,skipVer=True)
			verifyBlock(block4,startB)
			print()
	
			# ATTACK 4: MAJORITY 
			# user2 wants 8 back from user3 so rewrites transaction by mining own block:
			print("MAJORITY ATTACK: When user2 first rewrites the transaction, it is validated (not yet longest chain)")
			badt4 = Transaction(user2,[Input(t2,0),Input(t3,0)], [Output(user2.address,8.0),Output(user2.address,1.0)])
			badBlock2 = Block([t3,badt4],parent=block1,minerAddress=user2.address)
			print(verifyBlock(badBlock2,startB))
			print()
	
			# user2 also happens to mine another block right after this transaction:
			t_after = Transaction(user1,[Input(t2,1)],[Output(user3.address,5.0),Output(user1.address,10.0)])
			badBlock3 = Block([t_after], parent=badBlock2, minerAddress=user2.address)
	
			print("Now that user2 has mined another block, the chain length for the bad block is greater")
			print("Chain Length (Block2): %d" % chainLength(block2))
			print("Chain Length (Bad Block3): %d" % chainLength(badBlock3))
	
			# bad block is longer so user2 has sucessfully rewritten the ledger
			go = int(input("\nPlease Enter 1 to return to Main Menu Options and 0 to Quit\n"))
	
	
if __name__ == "__main__":
	main()
	
	
	
	