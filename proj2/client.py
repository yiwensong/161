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
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.public_key = self.pks.get_public_key(self.username)
        self.key_dict = dict()
        self.userdata = UserFile(self)
        self.filedb = self.userdata.get_file_db()
        self.user_prngseed = self.userdata.prngseed
        self.file_cache = {}

    def mac(self,message,key):
      return self.crypto.message_authentication_code(message, key, 'SHA512')

    def mac_verify(self,message,MAC,key):
      gmac = self.mac(message,key)
      if gmac != MAC:
        raise IntegrityError
      return True
    
    def sign(self, message):
      return self.crypto.asymmetric_sign(message, self.private_key)

    def verify(self, message, signature, key):
      if not self.crypto.asymmetric_verify(message, signature, key):
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

    def encrypt_a(self, message, key):
      return self.crypto.asymmetric_encrypt(message, key)

    def decrypt_a(self, ciphertext):
      return self.crypto.asymmetric_decrypt(ciphertext, self.private_key)

    def hash(self, message):
      return self.crypto.cryptographic_hash(message, 'SHA512')

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

    def make_json_a(self, data):
      try:
        json = to_json_string(data)
        sign = self.sign(json)
        signed = {'json':json,'sign':sign}
        signed_json = to_json_string(signed)
      except:
        raise IntegrityError
      return signed_json

    def retrieve_json_a(self, enc_json, ver_key):
      signed = from_json(enc_json)
      json = signed['json']
      sign = signed['sign']
      self.verify(json, sign, ver_key)
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
    
    def make_data_block(self,filename,data_seg,seed,block_num,name_only=False):
      _,genkey = self.gen_symm_keys(key=seed,n=3)
      key_e = get_key(genkey,0)
      key_m = get_key(genkey,1)
      key_n = get_key(genkey,2)
      name = filename + '.' + str(block_num) + '.data'
      name_on_server = self.mac(name, key_n)
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

    def upload(self,name,value):
      fd = self.filedb.get_fd(name)
      if fd is None or name not in self.file_cache or self.file_cache[name][0] != fd.nonce:
        if fd is None:
          fd = self.filedb.new_fd(name)
        fd.realloc(math.ceil(len(value) / BLOCK_SIZE))
        block_tuples = self.make_data_blocks(fd.filename, value, fd.prngseed)
        list(map(self.upload_block, block_tuples))
      else:
        fd.realloc(math.ceil(len(value) / BLOCK_SIZE))

        old = self.make_data_blocks(fd.filename, self.file_cache[name][1], fd.prngseed)
        new = self.make_data_blocks(fd.filename, value, fd.prngseed)
        for i in range(max(len(old), len(new))):
          if i >= len(old):
            self.upload_block(new[i])
            continue
          if i >= len(new):
            break

          old_data = self.get_block_info(fd.filename, old[i][1], fd.prngseed)['data']
          new_data = self.get_block_info(fd.filename, new[i][1], fd.prngseed)['data']

          if old_data != new_data:
            self.upload_block(new[i])
      self.file_cache[name] = [fd.nonce, value]

    def download(self, name):
      fd = self.filedb.get_fd(name)
      if fd is None:
        return None

      try:
        datablock_names = self.get_data_block_names(fd.filename, fd.prngseed, fd.num_blocks)
        dl_block = lambda n: self.download_block(fd.filename, n, fd.prngseed)
        datas = map(dl_block,datablock_names)
        data = reduce(lambda s1,s2:s1+s2,datas)
      except:
        raise IntegrityError

      return data
      

    def share(self, user, filename):
      fd = self.filedb.get_fd(filename)
      ptr = fd.share(user)
      encptr = self.encrypt_a(to_json_string(ptr), self.pks.get_public_key(user))
      signed = self.make_json_a(encptr)
      return signed

    def receive_share(self, from_username, newname, message):
      sharedFile = self.retrieve_json_a(message, self.pks.get_public_key(from_username))
      sharedFile = from_json(self.decrypt_a(sharedFile))
      ptr_name = sharedFile['f']
      enc_key = sharedFile['e']
      mac_key = sharedFile['m']
      
      self.filedb.get_share(newname, ptr_name, enc_key, mac_key)
      if newname in self.file_cache:
        del self.file_cache[newname]

    def revoke(self, user, name):
      data = self.download(name)
      del self.file_cache[name]

      oldfd = self.filedb.get_fd(name)
      newfd = self.filedb.new_fd(name)
      self.upload(name, data)

      for u, ssptrd in oldfd.sharelist.items():
        try:
          sptrd = self.retrieve_json_a(ssptrd, self.public_key)
          if user != u:
            newfd.sharelist[u] = sptrd
            sptr = SharePointer.from_dict(self, sptrd)
            sptr.parent = newfd.filename
            sptr.parent_encryption_key = newfd.encryption_key
            sptr.parent_mac_key = newfd.mac_key
            sptr.save()
        except IntegrityError:
          pass
        

      newfd.save()

class UserFile(object):
  def __init__(self, client):
    self.client = client
    self.username = self.client.username
    self.filename = self.client.hash('%s.userdata.%s' % (self.username, self.client.private_key.exportKey('DER')))
    self.load()

  def save(self):
    username_signed = self.client.sign(self.username)
    self.client.verify(self.username, username_signed, self.client.public_key)

    userdata = {
      'username': username_signed,
      'prngseed': self.client.encrypt_a(self.prngseed, self.client.public_key),
      'filedb': self.client.encrypt_a(self.file_db_path, self.client.public_key)
    }

    self.client.storage_server.put(self.filename, self.client.make_json_a(userdata))

  def load(self):
    ct = self.client.storage_server.get(self.filename)
    if ct is None:
      self.prngseed = self.client.crypto.get_random_bytes(KEYLEN)
      self.file_db_path = self.client.crypto.get_random_bytes(KEYLEN)
      self.save()
    else:
      userdata = self.client.retrieve_json_a(ct, self.client.public_key)
      self.client.verify(self.username, userdata['username'], self.client.public_key)
      self.prngseed = self.client.decrypt_a(userdata['prngseed'])
      self.file_db_path = self.client.decrypt_a(userdata['filedb'])

  def get_file_db(self):
    try:
      return self.filedb
    except AttributeError:
      self.filedb = FileDB(self)
      return self.filedb

class FileDB(object):
  def __init__(self, userfile):
    self.client = userfile.client

    k, gk = self.client.gen_symm_keys(key=userfile.prngseed, n=3)
    self.encryption_key = get_key(gk, 0)
    self.mac_key = get_key(gk, 1)
    self.filename = userfile.file_db_path
    self.load()

  def save(self):
    self.client.storage_server.put(self.filename, self.client.make_json(self.files, self.encryption_key, self.mac_key))

  def load(self):
    ct = self.client.storage_server.get(self.filename)
    if ct is None:
      self.files = {}
      self.save()
    else:
      filedb = self.client.retrieve_json(ct, self.encryption_key, self.mac_key)
      self.files = filedb

  def get_fd(self, filename):
    if not filename in self.files:
      return None

    if 's' in self.files[filename]:
      return SharePointer.from_dict(self.client, self.files[filename]).resolve()
    return FileDescriptor.from_dict(self.client, self.files[filename])

  def new_fd(self, filename):
    fd_name = self.client.gen_key()
    enc_key = self.client.gen_key()
    mac_key = self.client.gen_key()
    fd = FileDescriptor(self.client, fd_name, enc_key, mac_key)
    self.files[filename] = fd.to_dict()
    self.save()
    return fd

  def get_share(self, filename, ptr_name, enc_key, mac_key):
    ptr = SharePointer.load(self.client, ptr_name, enc_key, mac_key)
    self.files[filename] = ptr.to_dict()
    self.save()

class FileDescriptor(object):
  def __init__(self, client, filename, encryption_key, mac_key):
    self.client = client
    self.filename = filename
    self.encryption_key = encryption_key
    self.mac_key = mac_key
    self.load()

  @staticmethod
  def from_dict(client, obj):
    return FileDescriptor(client, obj['f'], obj['e'], obj['m'])

  def to_dict(self):
    return {
      'f': self.filename,
      'e': self.encryption_key,
      'm': self.mac_key
    }

  def save(self):
    self.nonce = self.client.gen_key()
    obj = {
      'prngseed': self.prngseed,
      'num_blocks': self.num_blocks,
      'sharelist': self.sharelist,
      'nonce': self.nonce
    }

    self.client.storage_server.put(self.filename, self.client.make_json(obj, self.encryption_key, self.mac_key))

  def load(self):
    ct = self.client.storage_server.get(self.filename)
    if ct is None:
      self.prngseed = self.client.gen_key()
      self.num_blocks = 0
      self.sharelist = {}
      self.save()
    else:
      fd = self.client.retrieve_json(ct, self.encryption_key, self.mac_key)
      self.prngseed = fd['prngseed']
      self.num_blocks = fd['num_blocks']
      self.sharelist = fd['sharelist']
      self.nonce = fd['nonce']

  def realloc(self, n):
    self.num_blocks = n
    self.save()

  def share(self, target):
    ptr_name = self.client.gen_key()
    ptr_enc_key = self.client.gen_key()
    ptr_mac_key = self.client.gen_key()

    ptr = SharePointer(self.client, ptr_name, ptr_enc_key, ptr_mac_key, self.filename, self.encryption_key, self.mac_key)
    ptr.save()
    ptrd = ptr.to_dict()
    self.sharelist[target] = self.client.make_json_a(ptrd)
    self.save()
    return ptrd

class SharePointer(FileDescriptor):
  def __init__(self, client, filename, encryption_key, mac_key, parent, parent_enc_key, parent_mac_key):
    self.client = client
    self.filename = filename
    self.encryption_key = encryption_key
    self.mac_key = mac_key
    self.parent = parent
    self.parent_encryption_key = parent_enc_key
    self.parent_mac_key = parent_mac_key

  @staticmethod
  def load(client, filename, encryption_key, mac_key):
    ct = client.storage_server.get(filename)
    ptr = client.retrieve_json(ct, encryption_key, mac_key)

    parent = ptr['p']
    parent_enc_key = ptr['e']
    parent_mac_key = ptr['m']

    return SharePointer(client, filename, encryption_key, mac_key, parent, parent_enc_key, parent_mac_key)

  @staticmethod
  def resolve_load(client, filename, encryption_key, mac_key):
    ct = client.storage_server.get(filename)
    ptr = client.retrieve_json(ct, encryption_key, mac_key)

    if 's' in ptr:
      return SharePointer.load(client, filename, encryption_key, mac_key)
    return FileDescriptor(client, filename, encryption_key, mac_key)

  @staticmethod
  def from_dict(client, obj):
    return SharePointer.load(client, obj['f'], obj['e'], obj['m'])

  def to_dict(self):
    return {
      's': True,
      'f': self.filename,
      'e': self.encryption_key,
      'm': self.mac_key
    }

  def save(self):
    obj = {
      's': True,
      'p': self.parent,
      'e': self.parent_encryption_key,
      'm': self.parent_mac_key
    }
    self.client.storage_server.put(self.filename, self.client.make_json(obj, self.encryption_key, self.mac_key))

  def resolve(self):
    while True:
      n = SharePointer.resolve_load(self.client, self.parent, self.parent_encryption_key, self.parent_mac_key)
      if type(n) == FileDescriptor:
        return n
