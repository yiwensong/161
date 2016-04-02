"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

IV_LEN = 16

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from util import *

KEYLEN = 16

class Client(BaseClient):

    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.public_key = self.pks.get_public_key(self.username)
        self.key_dict = dict()
    # self.username
    # self.storage_server
    # self.pks
    # self.crypto
    # self.private_key
    def get_storage_name(self,name):
      '''Makes $username->$name and $username->$name.key strings and hashes them
      so you can securely store it on the server'''
      storage_name = self.username + '->' + name
      name_hash = self.crypto.cryptographic_hash(storage_name,'SHA512')
      key_hash = self.crypto.cryptographic_hash(storage_name + '.key','SHA512')
      return name_hash,key_hash

    def gen_symm_keys(self,key=None,n=4):
      '''Generates symmetric key quadruples for use in CBC and MAC. Last two keys are currently unused.
      More or less used as a psuedorandom number generator.'''
      if key is None:
        key = self.crypto.get_random_bytes(KEYLEN)
      if n is None or n<4:
        n = 4

      if len(key) != KEYLEN*2:
        raise IntegrityError

      if key in self.key_dict:
        return self.key_dict[key]

      text = '\0'*n*KEYLEN
      counter = self.crypto.new_counter(KEYLEN*8)
      genkey = self.crypto.symmetric_encrypt(text,key,cipher_name='AES',mode_name='CTR',counter=counter)
      
      k1 = genkey[:KEYLEN*2]
      k2 = genkey[KEYLEN*2:4*KEYLEN]
      k3 = genkey[4*KEYLEN:6*KEYLEN]
      k4 = genkey[6*KEYLEN:]

      self.key_dict[key] = (key,k1,k2,k3,k4)

      return key,k1,k2,k3,k4

    def upload(self, name, value):
        ''' 1. Calculates symmetric keys
        2. Uploads the seed key and signature to $username->$name.key (enc with RSA Pr, signed with RSA Pr)
        3. Uploads the MAC, IV, and ciphertext to $username->$name (enc with k1, MAC with k2)'''
        k,k1,k2,k3,k4 = self.gen_symm_keys()

        name_hash,key_hash = self.get_storage_name(name)

        sym_key = k
        sym_key_enc = self.crypto.asymmetric_encrypt(sym_key,self.public_key)
        sym_key_sig = self.crypto.asymmetric_sign(sym_key_enc,self.private_key)
        keylen = chr(len(sym_key_sig))

        self.storage_server.put(key_hash,keylen + sym_key_sig + sym_key_enc)

        IV = self.crypto.get_random_bytes(IV_LEN)
        encrypted = self.crypto.symmetric_encrypt(value,k1,cipher_name='AES',mode_name='CBC',IV=IV)
        encrypted = IV + encrypted

        mac = self.crypto.message_authentication_code(value,k2,hash_name='SHA512')

        maclen = chr(len(mac))
        put_value = maclen + mac + encrypted
        self.storage_server.put(name_hash,put_value)


    def download(self, name):
        '''1. Finds the keys from $username->$name.key, checks integrity of k (RSA)
        2. Calculate symmetric keys with k
        3. Decrypt and MAC the message (k1,k2) '''
        name_hash,key_hash = self.get_storage_name(name)

        key_enc = self.storage_server.get(key_hash)
        if key_enc is None:
          return None

        keylen = ord(key_enc[0])

        sym_key_sig = key_enc[1:keylen+1]
        sym_key_enc = key_enc[keylen+1:]

        if not self.crypto.asymmetric_verify(sym_key_enc,sym_key_sig,self.public_key):
          raise IntegrityError

        k = self.crypto.asymmetric_decrypt(sym_key_enc,self.private_key)
        k,k1,k2,k3,k4 = self.gen_symm_keys(k)

        msg_enc = self.storage_server.get(name_hash)
        if msg_enc is None:
          return None

        maclen = ord(msg_enc[0])

        if len(msg_enc) < maclen + 1:
          raise IntegrityError

        try:
          mac = msg_enc[1:maclen+1]
          IV = msg_enc[maclen+1:maclen+1+IV_LEN*2]
          encrypted = msg_enc[maclen+1+IV_LEN*2:]
          value = self.crypto.symmetric_decrypt(encrypted,k1,cipher_name='AES',mode_name='CBC',IV=IV)
        except:
          raise IntegrityError
        if self.crypto.message_authentication_code(value,k2,hash_name='SHA512') != mac:
          raise IntegrityError
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
