"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError

class Client(BaseClient):
    KEYLEN = 16

    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.public_key = self.pks.get_public_key(self.username)
    # self.username
    # self.storage_server
    # self.pks
    # self.crypto
    # self.private_key
    def get_storage_name(username,name):
      storage_name = self.username + '\xba\x5e\xd6\x0d' + name
      return storage_name

    def gen_symm_keys(crypto,key=None):
      if key is None:
        key = crypto.get_random_bytes(Client.KEYLEN)

      text = '\0'*4*Client.KEYLEN
      counter = crypto.new_counter(Client.KEYLEN*8)
      genkey = crypto.symmetric_encrypt(text,key,cipher_name='AES',mode_name='CTR',counter=counter)
      
      k1 = genkey[:KEYLEN]
      k2 = genkey[KEYLEN:2*KEYLEN]
      k3 = genkey[2*KEYLEN:3*KEYLEN]
      k4 = genkey[3*KEYLEN:]

      return key,k1,k2,k3,k4

    def upload(self, name, value):
        # Replace with your implementation
        keychain = Client.gen_symm_keys(self.crypto)

        storage_name = self.username + '\xba\x5e\xd6\x0d' + name
        name_hash = self.crypto.cryptographic_hash(storage_name,'SHA512')

        sym_key = self.crypto.get_random_bytes(2048)
        encrypted = self.crypto.asymmetric_encrypt(value,self.public_key)

        sig = self.crypto.asymmetric_sign(encrypted,self.private_key)
        keylen = chr(len(sig))
        put_value = keylen + sig + encrypted
        self.storage_server.put(name_hash,put_value)

    def download(self, name):
        # Replace with your implementation
        storage_name = self.username + '\xba\x5e\xd6\x0d' + name
        name_hash = self.crypto.cryptographic_hash(storage_name,'SHA512')
        put_value = self.storage_server.get(name_hash)

        if put_value is None:
          return None

        try:
          keylen = ord(put_value[0])
        except:
          raise IntegrityError

        if len(put_value) < keylen+1:
          raise IntegriftyError

        sig = put_value[1:keylen+1]
        encrypted = put_value[keylen+1:]
        if not self.crypto.asymmetric_verify(encrypted,sig,self.public_key):
          raise IntegrityError

        value = self.crypto.asymmetric_decrypt(encrypted,self.private_key)
        return value

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
