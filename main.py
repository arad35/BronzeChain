from blockchain import *
import os

# addresses of all peers in network
PEERS = [("192.168.1.102", 51010), ("192.168.1.102", 51020)]
CONNECT_PORT = 51001
TIMEOUT = 15
HOP_MAX = 4


def start_bronzechain(name, balance=50, miner=False):
    """start the BronzeChain application
    return: the peer created"""

    # create peer and activate it
    my_peer = Peer(name, PEERS, CONNECT_PORT, balance=balance, miner=miner, hop_max=HOP_MAX)
    my_peer.start()
    return my_peer


def print_transactions(peer):
    while True:
        time.sleep(15)
        print("\n" * 3)
        print("verified transactions:")
        for transaction in peer.verified_transactions:
            print(transaction.to_json())
        print("\n" * 3)


def main():
    # Create a Peer instance
    my_name = input("your name: ")
    my_peer = start_bronzechain(my_name)

    watch_thread = threading.Thread(target=print_transactions, args=(my_peer, ))
    watch_thread.daemon = True
    watch_thread.start()
    while True:
        # Get user input
        name = input("Enter the name of the receiver: ")
        # receivers public key
        pass
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
