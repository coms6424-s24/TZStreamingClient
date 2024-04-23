import pyDHE


class insecure_key_storage:
    def __init__(self):
        self.my_key = pyDHE.new()
        self.shared_key = dict()

    def PublicKey(self):
        return self.my_key.getPublicKey()

    def compute_shared_key(self, client_address, public_key):
        self.shared_key[client_address] = self.my_key.update(public_key)

    def has_shared_key(self, client_address):
        return client_address in self.shared_key

    def encrypt(self, client_address, data):
        # TODO: encrypt data with shared key
        return self.shared_key[client_address].encrypt(data)


# https://cryptobook.nakov.com/key-exchange/dhke-examples
# https://zhuanlan.zhihu.com/p/599518034