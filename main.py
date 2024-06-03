from blockchain import *
import os

# addresses of all peers in network
PEERS = [("192.168.1.102", 50010), ("192.168.1.102", 50020)]
CONNECT_PORT = 50001
TIMEOUT = 15
HOP_MAX = 3


def start_bronzechain(name, balance=50, miner=False):
    """start the BronzeChain application
    return: the peer created"""

    # create peer and activate it
    my_peer = Peer(name, PEERS, CONNECT_PORT, balance=balance, miner=miner, time_out=TIMEOUT, hop_max=HOP_MAX)
    my_peer.main_loop()
    my_peer.send_hello(send_me_hello=True)
    return my_peer


def main():
    # Create a Peer instance
    my_name = input("your name: ")
    my_peer = start_bronzechain(my_name)

    while True:
        # Get user input
        name = input("Enter the name of the receiver: ")
        # receivers public key
        receiver = my_peer.fetch_public_key(name)
        if not receiver:
            print("Name not found in the peer database. Try again.")
            continue

        try:
            value = float(input("Enter the value of the transaction: "))
        except ValueError:
            print("Invalid value. Please enter a numeric value.")
            continue

        # Create the transaction
        transaction = my_peer.create_transaction(receiver, value)

        # Verify the transaction
        verification = my_peer.verify_transaction(transaction)
        if verification is True:
            print("Transaction verified successfully.")
            my_peer.send_transaction(transaction)
            my_peer.add_transaction(transaction)
            print("Transaction sent and added to verified transactions.")
        else:
            print(f"Transaction verification failed: {verification}")
            print(f"Transaction details: {transaction.to_json()}")


if __name__ == "__main__":
    main()
