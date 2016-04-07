"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from util import *

import math
from functools import reduce

IV_LEN = 16
KEYLEN = 16

BLOCK_SIZE = 2**8

def from_json(s):
  try:
    return from_json_string(s)
  except:
    raise IntegrityError


def get_key(genkey,block):
  return genkey[block*2*KEYLEN:(block+1)*2*KEYLEN]

class Client(BaseClient):

    def mac(self,message,key):
      return self.crypto.message_authentication_code(message,key,'SHA512')

    def mac_verify(self,message,MAC,key):
      gmac = self.mac(message,key)
      if gmac != MAC:
        raise IntegrityError
      return True
    
    def sign(self,message):
      return self.crypto.asymmetric_sign(message,self.private_key)

    def verify(self,message,signature):
      if not self.crypto.asymmetric_verify(message,signature,self.public_key):
        raise IntegrityError
      return True

    def encrypt(self,message,key):
      iv = self.crypto.get_random_bytes(IV_LEN)
      ciphertext = self.crypto.symmetric_encrypt(message,key,cipher_name='AES',mode_name='CBC',iv=iv)
      return iv + ciphertext

    def decrypt(self,ciphertext,key):
      iv = ciphertext[:2*IV_LEN]
      ct = ciphertext[2*IV_LEN:]
      message = self.crypto.symmetric_decrypt(ct,key,cipher_name='AES',mode_name='CBC',iv=iv)
      return message

    def encrypt_a(self,message):
      return self.crypto.asymmetric_encrypt(message,self.public_key)

    def decrypt_a(self,ciphertext):
      return self.crypto.asymmetric_decrypt(ciphertext,self.private_key)

    def hash(self,name,key):
      return self.mac(name,key)

    def make_json(self,data,enc_key,mac_key):
      json = to_json_string(data)
      MAC = self.mac(json,mac_key)
      macced = {'json':json,'mac':MAC}
      json_macced = to_json_string(macced)
      return self.encrypt(json_macced,enc_key)

    def retrieve_json(self,enc,enc_key,mac_key):
      try:
        json_macced = self.decrypt(enc,enc_key)
        macced = from_json(json_macced)
        json = macced['json']
        MAC = macced['mac']
        self.mac_verify(json,MAC,mac_key)
        data = from_json(json)
      except:
        raise IntegrityError
      return data

    def make_json_a(self,data):
      try:
        json = to_json_string(data)
        sign = self.sign(json)
        signed = {'json':json,'sign':sign}
        signed_json = to_json_string(signed)
      except:
        raise IntegrityError
      return signed_json

    def retrieve_json_a(self,enc_json):
      signed = from_json(enc_json)
      json = signed['json']
      sign = signed['sign']
      self.verify(json,sign)
      data = from_json(json)
      return data

    def gen_key(self):
      return self.crypto.get_random_bytes(KEYLEN)

    def gen_symm_keys(self,key=None,n=None):
      '''Generates symmetric key quadruples for use in CBC and MAC. Last two keys are currently unused.
      More or less used as a psuedorandom number generator.'''
      if key is None:
        key = self.gen_key()
      if n is None or n<6:
        n = 6
      if len(key) != KEYLEN*2:
        raise IntegrityError
      text = '\0'*n*KEYLEN
      counter = self.crypto.new_counter(KEYLEN*8)
      genkey = self.crypto.symmetric_encrypt(text,key,cipher_name='AES',mode_name='CTR',counter=counter)
      return key,genkey

    def make_meta_block(self,filename,data,seed,name_only=False,prngseed=None):
      _,genkey = self.gen_symm_keys(key=seed,n=3)
      key_e = get_key(genkey,0)
      key_m = get_key(genkey,1)
      key_n = get_key(genkey,2)
      name = self.username + '.' + filename + '.' + 'meta' 
      name_on_server = self.hash(name,key_n)
      if name_only:
        return name_on_server
      num_blocks = math.ceil(len(data) / BLOCK_SIZE)
      if prngseed is None:
        prngseed = self.gen_key()
      sharelist = []
      info = {'filename':filename,\
          'prngseed':prngseed,\
          'num_blocks':num_blocks,\
          'sharelist':sharelist}
      try:
        upload_this = self.make_json(info,key_e,key_m)
      except:
        raise IntegrityError
      return name_on_server, upload_this
    
    def make_data_block(self,filename,data_seg,seed,block_num,name_only=False):
      _,genkey = self.gen_symm_keys(key=seed,n=3)
      key_e = get_key(genkey,0)
      key_m = get_key(genkey,1)
      key_n = get_key(genkey,2)
      name = self.username + '.' + filename + '.' + str(block_num) + '.data'
      name_on_server = self.hash(name,key_n)
      if name_only:
        return name_on_server
      salt = self.gen_key()
      info = {'filename': filename,\
          'block_num': block_num,\
          'data': data_seg,\
          'salt': salt}
      upload_this = self.make_json(info,key_e,key_m)
      return name_on_server,upload_this

    def make_data_blocks(self,filename,data,seed,name_only=False):
      num_blocks = math.ceil(len(data)/BLOCK_SIZE)
      blocks = [('','')] * num_blocks
      for i in range(num_blocks):
        data_seg = data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
        blocks[i] = self.make_data_block(filename,data_seg,seed,i,name_only)
      return blocks

    def get_data_block_names(self,filename,seed,num_blocks):
      get_name = lambda i: self.make_data_block(filename,None,seed,i,True)
      names = map(get_name,range(num_blocks))
      return names

    def get_block_info(self,filename,downloaded,seed):
      _,genkey = self.gen_symm_keys(key=seed,n=3)
      key_e = get_key(genkey,0)
      key_m = get_key(genkey,1)
      key_n = get_key(genkey,2)
      data = self.retrieve_json(downloaded,key_e,key_m)
      if data['filename'] != filename:
        raise IntegrityError
      return data

    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.public_key = self.pks.get_public_key(self.username)
        self.key_dict = dict()
        ud_name = self.username + '.userdata'
        userdata = self.storage_server.get(ud_name)
        if userdata is None:
          prngseed = self.crypto.get_random_bytes(KEYLEN)
          username_signed = self.sign(self.username)
          self.verify(self.username,username_signed)
          prngseed_aenc = self.encrypt_a(prngseed)
          userdata = {'username':username_signed,\
              'prngseed':prngseed_aenc}
          upload = self.make_json_a(userdata)
          self.storage_server.put(ud_name,upload)
        else:
          userdata = self.retrieve_json_a(userdata)
          self.verify(self.username,userdata['username'])
          prngseed = self.decrypt_a(userdata['prngseed'])
        self.user_prngseed = prngseed
        self.file_cache = {}

    def upload_block(self,block_tuple):
      name_on_server = block_tuple[0]
      data = block_tuple[1]
      self.storage_server.put(name_on_server,data)
      return

    def download_block(self,name,hashname,seed):
      raw = self.storage_server.get(hashname)
      if raw is None:
        return None
      data = self.get_block_info(name,raw,seed)
      return data['data']

    def clean_upload(self, name, value):
      metaname,metadata = self.make_meta_block(name,value,self.user_prngseed)
      metainfo = self.get_block_info(name,metadata,self.user_prngseed)
      self.storage_server.put(metaname,metadata)
      seed = metainfo['prngseed']
      block_tuples = self.make_data_blocks(name,value,seed)
      list(map(self.upload_block,block_tuples))

    def upload(self,name,value):
      if name not in self.file_cache:
        self.clean_upload(name,value)
        self.file_cache[name] = value
        return

      metaname = self.make_meta_block(name,None,self.user_prngseed,True)
      metablock = self.storage_server.get(metaname)
      meta_info = self.get_block_info(name,metablock,self.user_prngseed)
      seed = meta_info['prngseed']
      old = self.make_data_blocks(name,self.file_cache[name],seed)
      new = self.make_data_blocks(name,value,seed)
      for i in range(min(len(old),len(new))):
        old_data = self.get_block_info(name,old[i][1],seed)['data']
        new_data = self.get_block_info(name,new[i][1],seed)['data']
        if old_data != new_data:
          self.upload_block(new[i])
      self.file_cache[name] = value
      newmeta = self.make_meta_block(name,value,self.user_prngseed,prngseed=seed)
      self.upload_block(newmeta)
      return



    def download(self, name):
      metaname = self.make_meta_block(name,None,self.user_prngseed,True)
      value = self.storage_server.get(metaname)
      if value is None:
        return None
      try:
        metainfo = self.get_block_info(name,value,self.user_prngseed)
        seed = metainfo['prngseed']
        blocks = metainfo['num_blocks']
        datablock_names = self.get_data_block_names(name,seed,blocks)
        dl_block = lambda n: self.download_block(name,n,seed)
        datas = map(dl_block,datablock_names)
        data = reduce(lambda s1,s2:s1+s2,datas)
      except:
        raise IntegrityError
      return data
      

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
