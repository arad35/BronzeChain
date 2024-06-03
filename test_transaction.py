import json
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from datetime import datetime
import hashlib
import binascii


def sha256(message):
    """hashes a message
    returns hash as a string"""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()


class Peer:
    """Represents a peer in the blockchain network"""

    def __init__(self, name, balance=50):

        # identity properties
        self.name = name
        self.balance = balance
        self._private_key = RSA.generate(1024)
        self._public_key = self._private_key.public_key()

    @property
    def identity(self):
        """Hexadecimal representation of public key"""
        return binascii.hexlify(self._public_key.export_key()).decode("utf-8")

    @property
    def signer(self):
        return PKCS1_v1_5.new(self._private_key)


class Transaction:
    """A class for representing a transaction"""

    def __init__(self, sender: RSA.RsaKey, receiver: RSA.RsaKey, value: float,
                 timestamp: datetime, tx_hash: str, signature: str):

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
        """Create a transaction object from JSON data"""
        data = json.loads(json_data)
        sender = RSA.import_key(binascii.unhexlify(data["sender"]))
        receiver = RSA.import_key(binascii.unhexlify(data["receiver"]))
        value = data["value"]
        timestamp = datetime.fromisoformat(data["timestamp"])
        tx_hash, signature = data["tx_hash"], data["signature"]

        return cls(sender, receiver, value, timestamp, tx_hash, signature)

    @classmethod
    def create_transaction(cls, sender, receiver, value, signer):
        """Create a new transaction
        sender: sender's private key
        receiver: receiver's private key
        value: amount to be transferred
        signer: peer's signer object"""
        timestamp = datetime.now()
        data = f"{sender.export_key().decode()}{receiver.export_key().decode()}{value}{timestamp.isoformat()}"
        tx_hash = hashlib.sha256(data.encode()).hexdigest()
        signature = cls.sign(data, signer)
        return cls(sender, receiver, value, timestamp, tx_hash, signature)

    @staticmethod
    def sign(data, signer):
        """sign the transaction using the user's private key
        data: transaction data
        signer: peer's signer object"""
        h = SHA256.new(data.encode('utf-8'))
        return binascii.hexlify(signer.sign(h)).decode('ASCII')


# Test the transaction class
if __name__ == "__main__":
    # Create 3 peers
    alice = Peer("Alice")
    bob = Peer("Bob")
    charlie = Peer("Charlie")

    # Create transactions between them
    transaction1 = Transaction.create_transaction(alice._private_key, bob._private_key, 10, alice.signer)
    transaction2 = Transaction.create_transaction(bob._private_key, charlie._private_key, 20, bob.signer)
    transaction3 = Transaction.create_transaction(charlie._private_key, alice._private_key, 15, charlie.signer)

    # Dump each transaction to JSON and load it back to a Transaction object
    for transaction in [transaction1, transaction2, transaction3]:
        json_data = transaction.to_json()
        print("Serialized Transaction:")
        print(json_data)

        deserialized_transaction = Transaction.from_json(json_data)
        print("\nDeserialized Transaction:")
        print(deserialized_transaction.to_json())
        print("\n")