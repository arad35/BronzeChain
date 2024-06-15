from blockchain import *
import re

# addresses of all peers in network
PEERS = [("localhost", 60001), ("localhost", 60010)]
CONNECT_PORT = 60020
TIMEOUT = 15
HOP_MAX = 4
my_peer = None


def start_bronzechain(name, balance=50, miner=True):
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


def replace_keys_with_names(data, peer: Peer):
    """use regex logic to replace public keys of peers with name"""
    pattern = re.compile(r'(sender|receiver|miner): (\w+)')

    def replace(match):
        if match.group(2) == peer.identity:
            # public key of the user, replace with username
            return f"{match.group(1)} : {peer.name}"

        name = peer.fetch_name(match.group(2))
        if name: return f"{match.group(1)} : {name}" # found a name corresponding to key

        # return original string
        return match.group()

    return pattern.sub(replace, data)


def main():
    # Create a Peer instance
    my_name = input("your name: ")
    my_peer = start_bronzechain(my_name, miner=True)

    # watch_thread = threading.Thread(target=print_transactions, args=(my_peer, ))
    # watch_thread.daemon = True
    # watch_thread.start()

    while True:
        command = input("show or send: ")

        if command.lower() == "send":
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

            if value > my_peer.balance:
                print("can't send more than your balance")
                continue

            # Create the transaction
            transaction = my_peer.create_transaction(receiver, value)

            # Verify the transaction
            verification = my_peer.verify_transaction(transaction)
            if verification is True:  # check if the verification is the boolean True (and not some string)
                print("Transaction verified successfully.")
                my_peer.send_transaction(transaction)
                my_peer.add_transaction(transaction)
                print("Transaction sent and added to verified transactions.")
            else:
                print(f"Transaction verification failed: {verification}")
                print(f"Transaction details: {transaction.to_json()}")

        elif command.lower() == "show":
            property_name = input("Enter a property to show: ")

            try:
                data = getattr(my_peer, property_name)
            except AttributeError:
                print(f"Property '{property_name}' does not exist.")
                continue

            if isinstance(data, list):
                string_data = '[\n' + ",\n".join(str(tx) for tx in data) + '\n]'
            else:
                string_data = str(data)

            sub_string_data = replace_keys_with_names(string_data, my_peer)

            print(f"{property_name}:")
            print(sub_string_data)

        else:
            print(f"no such command: {command}")


if __name__ == "__main__":
    main()
