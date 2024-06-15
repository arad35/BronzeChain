from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import threading
from socket import *
import copy
import binascii
from datetime import datetime
import hashlib
import json
from typing import List
import traceback
import time


def sha256(message):
    """hashes a message
    returns hash as a string"""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()


class Transaction:
    """A class for representing a transaction"""

    def __init__(self, sender: RSA.RsaKey, receiver: RSA.RsaKey, value: float,
                 timestamp: datetime, tx_hash: str, signature: str):
        """transaction initialization by directly assigning properties"""
        # sender and receiver public keys
        self.sender = sender
        self.receiver = receiver

        self.value = value
        self.timestamp = timestamp
        self.tx_hash = tx_hash
        self.signature = signature

    def to_json(self):
        """return json representation of the transaction"""
        return json.dumps({
            "sender": binascii.hexlify(self.sender.export_key()).decode(),
            "receiver": binascii.hexlify(self.receiver.export_key()).decode(),
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "tx_hash": self.tx_hash,
            "signature": self.signature
        })

    @classmethod
    def from_json(cls, json_data):
        """creates and returns a transaction object from json data"""
        # load data
        data = json.loads(json_data)
        sender = RSA.import_key(binascii.unhexlify(data["sender"]))
        receiver = RSA.import_key(binascii.unhexlify(data["receiver"]))
        value = data["value"]
        timestamp = datetime.fromisoformat(data["timestamp"])
        tx_hash, signature = data["tx_hash"], data["signature"]
        return cls(sender, receiver, value, timestamp, tx_hash, signature)

    @classmethod
    def create_transaction(cls, sender, receiver, value, signer):
        """creates a new transaction
        sender: sender's public key
        receiver: receiver's public key
        value: amount to be transferred
        signer: peer's signer object
        returns: new transaction"""
        timestamp = datetime.now()
        data = f"{binascii.hexlify(sender.export_key()).decode()}{binascii.hexlify(receiver.export_key()).decode()}{value}{timestamp.isoformat()}"
        tx_hash = sha256(data)
        signature = cls._sign(data, signer)
        return cls(sender, receiver, value, timestamp, tx_hash, signature)

    @staticmethod
    def _sign(data, signer):
        """sign the transaction using the user's private key
        private method
        data: transaction data
        signer: peer's signer object
        return: signature in string format"""
        h = SHA256.new(data.encode('utf-8'))
        return binascii.hexlify(signer.sign(h)).decode('ASCII')

    def __repr__(self):
        """string representation of a transaction"""
        data = json.loads(self.to_json())

        return (
            f"Transaction\n"
            f"  sender: {data['sender']}\n"
            f"  receiver: {data['receiver']}\n"
            f"  value: {data['value']}\n"
            f"  timestamp: {data['timestamp']}\n"
            f"  tx Hash: {data['tx_hash']}\n"
            f"  signature: {data['signature']}"
        )

    def __str__(self):
        return self.__repr__()


class RewardTransaction(Transaction):
    """special transaction for rewarding a miner"""

    def __init__(self, sender: RSA.RsaKey, receiver: RSA.RsaKey, value: float,
                 timestamp: datetime, tx_hash: str, signature: str):
        """transaction initialization by directly assigning properties"""
        # sender and receiver public keys
        self.sender = sender
        self.receiver = receiver

        self.value = value
        self.timestamp = timestamp
        self.tx_hash = tx_hash
        self.signature = signature


class Block:
    """A class for representing a single block"""

    def __init__(self, transactions: List[Transaction], tx_count, tx_hash_root: str,
                 difficulty: int, reward: float, previous_hash: str,
                 nonce: int = None, miner: RSA.RsaKey = None, timestamp: datetime = None):
        """block initialization by directly assigning properties
        nonce, miner and timestamp are None in case block was not yet mined"""

        self.transactions = copy.copy(transactions)

        self.tx_count = tx_count
        # root of transaction hashes
        self.tx_hash_root = tx_hash_root
        self.difficulty = difficulty
        self.reward = reward
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.miner = miner
        self.timestamp = timestamp

    def to_json(self):
        """return json representation of the block"""
        dict_data = {
            "tx_count": self.tx_count,
            "tx_hash_root": self.tx_hash_root,
            "difficulty": self.difficulty,
            "reward": self.reward,
            "previous_hash": self.previous_hash,
            "transactions": [tx.to_json() for tx in self.transactions]}

        try:
            miner_dict = {
                "miner": binascii.hexlify(self.miner.export_key()).decode(),
                "nonce": self.nonce,
                "timestamp": self.timestamp.isoformat()}

        except AttributeError:
            # block wasn't mined yet
            miner_dict = {"miner": None, "nonce": None, "timestamp": None}

        finally:
            dict_data.update(miner_dict)
            return json.dumps(dict_data)

    @classmethod
    def from_json(cls, json_data):
        """create and return Block object from json data"""
        data = json.loads(json_data)
        transactions = [Transaction.from_json(tx) for tx in data["transactions"]]
        tx_count = data["tx_count"]
        tx_hash_root = data["tx_hash_root"]
        difficulty = data["difficulty"]
        reward = data["reward"]
        previous_hash = data["previous_hash"]
        nonce = data["nonce"]

        try:
            miner = RSA.import_key(binascii.unhexlify(data["miner"]))
        except ValueError:
            # block wasn't mined yet
            miner = None

        try:
            timestamp = datetime.fromisoformat(data["timestamp"])
        except ValueError:
            # timestamp not created yet
            timestamp = None

        return cls(transactions, tx_count, tx_hash_root, difficulty, reward, previous_hash, nonce, miner, timestamp)

    @classmethod
    def create_block(cls, transactions, difficulty, reward, previous_hash):
        """creates and returns a new block"""
        tx_count = len(transactions)
        tx_hash_root = cls._compute_tx_hash_root(transactions)

        return cls(transactions, tx_count, tx_hash_root, difficulty, reward, previous_hash)

    @staticmethod
    def _compute_tx_hash_root(transactions):
        """computes and returns transaction hash root for a transaction list
        private method
        transactions: a list of transactions"""
        concatenated_hash = ''.join([tx.tx_hash for tx in transactions])
        return sha256(concatenated_hash)

    def compute_tx_hash_root(self):
        """Compute and return transaction hash root for the block's transactions"""
        return self._compute_tx_hash_root(self.transactions)

    def compute_hash(self):
        """computes and returns the hash of the block"""
        block_data = f"{self.tx_count}{self.tx_hash_root}{self.difficulty}{self.reward}{self.previous_hash}{self.nonce}"
        return sha256(block_data)

    def validate_difficulty(self):
        """checks if hash of block suits difficulty
        returns: a boolean indicating whether hash suits difficulty"""
        block_hash = self.compute_hash()
        if block_hash.endswith("0" * self.difficulty):
            return True
        else:
            return False

    def mine(self, miner):
        """Implements proof of work: finds a suitable nonce that satisfies difficulty
        miner: public key of miner
        updates: nonce, miner and timestamp properties"""
        self.nonce = 0
        success = self.validate_difficulty()

        while not success:
            self.nonce += 1
            success = self.validate_difficulty()

        self.miner = miner
        self.timestamp = datetime.now()

    def __repr__(self):
        """string representation of a block"""
        # string containing the transactions
        transactions_string = ""
        i = 0
        for transaction in self.transactions:
            transactions_string += f"transaction #{i}: {transaction}\n"
            i += 1

        data = json.loads(self.to_json())
        return (
            f"Block\n"
            f"  transactions: {transactions_string[:-1]}\n"
            f"  tx_count: {data['tx_count']}\n"
            f"  tx_hash_root: {data['tx_hash_root']}\n"
            f"  difficulty: {data['difficulty']}\n"
            f"  reward: {data['reward']}\n"
            f"  previous hash: {data['previous_hash']}\n"
            f"  nonce: {data['nonce']}\n"
            f"  miner: {data['miner']}\n"
            f"  timestamp: {data['timestamp']}"
        )

    def __str__(self):
        return self.__repr__()


class Blockchain:
    """Represents the entire blockchain"""

    def __init__(self, min_transactions, max_transactions, difficulty, reward):
        """Initialize blockchain with the genesis block"""
        self.chain: List[Block] = []
        self.last_hash = ""
        self.height = 0

        self.verified_transactions = []

        self.min_transactions = min_transactions
        self.max_transactions = max_transactions
        self.difficulty = difficulty
        self.reward = reward

    def can_create_block(self):
        """return a boolean indicating whether a new block can be created"""
        return len(self.verified_transactions) >= self.min_transactions

    def create_new_block(self):
        """create and return new block linked to the previous"""
        tx_count = min(self.max_transactions, len(self.verified_transactions))
        transactions = self.verified_transactions[:tx_count]

        new_block = Block.create_block(transactions, self.difficulty, self.reward, self.last_hash)
        print("\nnew block created:\n", new_block)
        return new_block

    def mine_block(self, block, miner):
        """mine a block
        block: the block
        miner: public key of miner"""
        block.mine(miner)
        print("\nblock mined:\n", block)

    def add_block_to_chain(self, block):
        """Add a block to the blockchain if valid"""
        self.chain.append(block)
        self.last_hash = block.compute_hash()
        self.height += 1
        print("\nblock added to chain:\n", block)

    # additional utility functions
    def get_last_block(self):
        """Get the last block in the blockchain"""
        return self.chain[-1]

    def is_chain_valid(self):
        """Check the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.previous_hash != previous_block.compute_hash():
                return False

            if not current_block.validate_difficulty():
                return False

        return True

    def verify_block(self, block: Block, transaction_verifier):
        """Comprehensive validation of a block before adding to the chain
        block: block to be verified
        transaction_verifier: function for verifying transactions
        returns: True if block verified successfully, error message otherwise"""

        # check if amount of transactions is suitable
        if block.tx_count != len(block.transactions):
            return "transaction count is invalid"
        if block.tx_count < self.min_transactions:
            return "not enough transactions in block"
        if block.tx_count > self.max_transactions:
            return "too much transactions in block"

        # verify previous hash (unless it is the first block in chain)
        if self.height > 0:
            if block.previous_hash != self.last_hash:
                return "previous hash is invalid"

        # verify proof of work
        if not block.validate_difficulty():
            return "proof of work is invalid"

        # verify transaction hash root
        if block.tx_hash_root != block.compute_tx_hash_root():
            return "transaction hash root is invalid"

        # verify every transaction
        for transaction in block.transactions:
            tx_verification = transaction_verifier(transaction)
            if isinstance(tx_verification, str):
                # return error message with problematic transaction
                return f"{tx_verification}:\n{transaction}"

        return True

    def __repr__(self):
        # string containing the blocks
        blocks_string = ""
        i = 0
        for blocks in self.chain:
            blocks_string += f"transaction #{i}: {blocks}\n"
            i += 1

        return (
            f"Blockchain\n"
            f"  blocks: {blocks_string[:-1]}\n"
            f"  last hash: {self.last_hash}\n"
            f"  height: {self.height}\n"
            f"  min transactions: {self.min_transactions}\n"
            f"  max transactions: {self.max_transactions}\n"
            f"  difficulty: {self.difficulty}\n"
            f"  reward: {self.reward}"
        )

    def __str__(self):
        return self.__repr__()

