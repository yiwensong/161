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
import binascii
import base64

import math

IV_LEN = 16
KEYLEN = 16

BLOCK_SIZE = 2**10

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
      json_enc = self.encrypt(json, enc_key)
      MAC = self.mac(json_enc,mac_key)
      return MAC + json_enc

    def retrieve_json(self,enc,enc_key,mac_key):
      try:
        MAC = enc[:128]
        json_enc = enc[128:]
        self.mac_verify(json_enc, MAC, mac_key)
        json = self.decrypt(json_enc, enc_key)
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

    def keys_from_prng(self, prngseed):
      k, gk = self.client.gen_symm_keys(key=userfile.prngseed, n=3)
      return get_key(gk, 0), get_key(gk, 1)

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
    
    def b64_id(self, msg):
      return base64.b64encode(binascii.unhexlify(msg)).decode('ascii')

    def unb64_id(self, msg):
      return binascii.hexlify(base64.b64decode(msg.encode('ascii'))).decode('ascii')

    def put_raw(self, key, value):
      self.storage_server.put(self.b64_id(key), self.b64_id(value))

    def get_raw(self, key):
      d = self.storage_server.get(self.b64_id(key))
      if d is None:
        return d
      return self.unb64_id(d)

    def make_data_block(self, filename, data_seg, enc_key, mac_key, block_num):
      info = {'f': self.b64_id(filename) + str(block_num),
              'd': data_seg}
      upload_this = self.make_json(info,enc_key,mac_key)
      return self.get_data_block_name(filename, mac_key, block_num), upload_this

    def make_data_blocks(self,filename,data,enc_key,mac_key):
      num_blocks = math.ceil(len(data)/BLOCK_SIZE)
      return [self.make_data_block(filename, data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE], enc_key, mac_key, i) for i in range(num_blocks)]

    def get_data_block_name(self, filename, mac_key, block_num):
      name = filename + '.' + str(block_num) + '.data'
      return self.mac(name, mac_key)

    def get_data_block_names(self,filename,enc_key,mac_key,num_blocks):
      get_name = lambda i: self.get_data_block_name(filename, mac_key, i)
      names = map(get_name, range(num_blocks))
      return names

    def get_block(self, filename, downloaded, enc_key, mac_key, block_num):
      data = self.retrieve_json(downloaded, enc_key, mac_key)

      vname = self.b64_id(filename)
      dataname = data['f'][:len(vname)]
      block_num = data['f'][len(vname):]

      if dataname != vname or block_num != str(block_num):
        raise IntegrityError
      return data['d']

    def upload_block(self, block_tuple):
      name_on_server = block_tuple[0]
      data = block_tuple[1]
      self.put_raw(name_on_server,data)
      return

    def download_block(self, name, hashname, enc_key, mac_key, block_num):
      raw = self.get_raw(hashname)
      if raw is None:
        return None
      data = self.get_block(name, raw, enc_key, mac_key, block_num)
      return data

    def upload(self,name,value):
      fd = self.filedb.get_fd(name)
      dirty_blocks = None
      if fd:
        tl = fd.get_tl()
        if tl:
          dirty_blocks = tl.get_dirty(self.file_cache[name][0])

      if fd is None:
        fd = self.filedb.new_fd(name)
        fd.realloc(math.ceil(len(value) / BLOCK_SIZE))
        block_tuples = self.make_data_blocks(fd.filename, value, fd.encryption_key, fd.mac_key)
        list(map(self.upload_block, block_tuples))
        fd.save()
      elif name not in self.file_cache or (dirty_blocks is None and self.file_cache[name][0] != fd.nonce):
        fd.nonce = self.gen_key()
        fd.log = None
        fd.realloc(math.ceil(len(value) / BLOCK_SIZE))
        block_tuples = self.make_data_blocks(fd.filename, value, fd.encryption_key, fd.mac_key)
        list(map(self.upload_block, block_tuples))
        fd.save()
      else:
        fd.nonce = self.gen_key()
        fd.realloc(math.ceil(len(value) / BLOCK_SIZE))

        changed_blocks = set()

        old = self.make_data_blocks(fd.filename, self.file_cache[name][1], fd.encryption_key, fd.mac_key)
        new = self.make_data_blocks(fd.filename, value, fd.encryption_key, fd.mac_key)
        for i in range(max(len(old), len(new))):
          if i >= len(new):
            break
          if (dirty_blocks and i in dirty_blocks):
            data = self.download_single_block(fd, i)
            new_data = self.get_block(fd.filename, new[i][1], fd.encryption_key, fd.mac_key, i)
            if data != new_data:
              self.upload_block(new[i])
              changed_blocks.add(i)
            continue
          if i >= len(old):
            self.upload_block(new[i])
            changed_blocks.add(i)
            continue

          old_data = self.get_block(fd.filename, old[i][1], fd.encryption_key, fd.mac_key, i)
          new_data = self.get_block(fd.filename, new[i][1], fd.encryption_key, fd.mac_key, i)

          if old_data != new_data:
            self.upload_block(new[i])
            changed_blocks.add(i)

        new_tl = fd.make_tl()
        new_tl.changes = list(changed_blocks)
        new_tl.save()

      self.file_cache[name] = [fd.nonce, value]

    def download_single_block(self, fd, index):
      name = self.get_data_block_name(fd.filename, fd.mac_key, index)
      return self.download_block(fd.filename, name, fd.encryption_key, fd.mac_key, index)

    def download(self, name):
      fd = self.filedb.get_fd(name)
      if fd is None:
        return None

      try:
        datablock_names = enumerate(self.get_data_block_names(fd.filename, fd.encryption_key, fd.mac_key, fd.num_blocks))
        dl_block = lambda n: self.download_block(fd.filename, n[1], fd.encryption_key, fd.mac_key, n[0])
        data = ''.join(map(dl_block, datablock_names))
      except:
        raise IntegrityError

      self.file_cache[name] = [fd.nonce, data]
      return data

    def share(self, user, filename):
      fd = self.filedb.get_fd_raw(filename)
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
      self.download(newname)

    def revoke(self, user, name):
      data = self.download(name)
      del self.file_cache[name]

      oldfd = self.filedb.get_fd(name)
      newfd = self.filedb.new_fd(name)
      self.upload(name, data)
      sharelist = ShareList(self, oldfd)
      del sharelist.sharelist[user]
      sharelist.fd = newfd
      sharelist.gen_filename()

      for sd in sharelist.sharelist.values():
        sp = SharePointer.from_dict(self, sd)
        sp.parent = newfd.filename
        sp.parent_encryption_key = newfd.encryption_key
        sp.parent_mac_key = newfd.mac_key
        sp.save()

      sharelist.save()
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
    self.client.put_raw(self.filename, self.client.make_json(self.files, self.encryption_key, self.mac_key))

  def load(self):
    ct = self.client.get_raw(self.filename)
    if ct is None:
      self.files = {}
      self.save()
    else:
      self.files = self.client.retrieve_json(ct, self.encryption_key, self.mac_key)

  def get_fd(self, filename):
    if not filename in self.files:
      return None

    if 's' in self.files[filename]:
      return SharePointer.from_dict(self.client, self.files[filename]).resolve()
    return FileDescriptor.from_dict(self.client, self.files[filename])

  def get_fd_raw(self, filename):
    if not filename in self.files:
      return None

    if 's' in self.files[filename]:
      return SharePointer.from_dict(self.client, self.files[filename])
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
    obj = {
      '#': self.num_blocks,
      'l': self.log,
      'n': self.nonce
    }

    self.client.put_raw(self.filename, self.client.make_json(obj, self.encryption_key, self.mac_key))

  def load(self):
    ct = self.client.get_raw(self.filename)
    if ct is None:
      self.prngseed = self.client.gen_key()
      self.num_blocks = 0
      self.log = None
      self.nonce = self.client.gen_key()
      self.save()
    else:
      fd = self.client.retrieve_json(ct, self.encryption_key, self.mac_key)
      self.num_blocks = fd['#']
      self.log = fd['l']
      self.nonce = fd['n']

  def realloc(self, n):
    self.num_blocks = n

  def share(self, target):
    ptr_name = self.client.gen_key()
    ptr_enc_key = self.client.gen_key()
    ptr_mac_key = self.client.gen_key()

    ptr = SharePointer(self.client, ptr_name, ptr_enc_key, ptr_mac_key, self.filename, self.encryption_key, self.mac_key)
    ptr.save()
    ptrd = ptr.to_dict()
    sharelist = ShareList(self.client, self)
    sharelist.sharelist[target] = ptrd
    sharelist.save()
    return ptrd

  def get_tl(self):
    return TransactionLog.load_log(self.client, self)

  def make_tl(self):
    tl = TransactionLog.make_log(self.client, self)
    self.log = tl.get_dict()
    self.save()
    return tl

class ShareList(object):
  def __init__(self, client, fd):
    self.client = client
    self.fd = fd
    self.gen_filename()
    self.encryption_key = self.client.filedb.encryption_key
    self.mac_key = self.client.filedb.mac_key
    self.load()

  def gen_filename(self):
    self.filename = self.client.mac('%s.sharing' % self.fd.filename, self.client.userdata.prngseed)

  def save(self):
    self.client.put_raw(self.filename, self.client.make_json(self.sharelist, self.encryption_key, self.mac_key))

  def load(self):
    ct = self.client.get_raw(self.filename)
    if ct is None:
      self.sharelist = {}
    else:
      self.sharelist = self.client.retrieve_json(ct, self.encryption_key, self.mac_key)

class TransactionLog(object):
  def __init__(self, client, filename, enc_key, mac_key, nonce, next_log, next_enc_key, next_mac_key):
    self.client = client
    self.filename = filename
    self.encryption_key = enc_key
    self.mac_key = mac_key
    self.nonce = nonce
    self.next_log = next_log
    self.next_encryption_key = next_enc_key
    self.next_mac_key = next_mac_key

  @staticmethod
  def make_log(client, fd):
    filename = client.gen_key()
    enc_key = client.gen_key()
    mac_key = client.gen_key()

    if not fd.log:
      return TransactionLog(client, filename, enc_key, mac_key, fd.nonce, None, None, None)
    else:
      return TransactionLog(client, filename, enc_key, mac_key, fd.nonce, fd.log['f'], fd.log['e'], fd.log['m'])

  @staticmethod
  def load_log(client, fd):
    fdlog = fd.log
    if fdlog is None:
      return None

    return TransactionLog.load(client, fdlog['f'], fdlog['e'], fdlog['m'])

  @staticmethod
  def load(client, filename, encryption_key, mac_key):
    ct = client.get_raw(filename)
    if ct is None:
      return None
    log = client.retrieve_json(ct, encryption_key, mac_key)
    tl = TransactionLog(client, filename, encryption_key, mac_key, log['n'], log['f'], log['e'], log['m'])
    tl.changes = log['c']
    return tl

  def get_dict(self):
    return {
      'f': self.filename,
      'e': self.encryption_key,
      'm': self.mac_key
    }

  def save(self):
    obj = {
      'c': self.changes,
      'f': self.next_log,
      'e': self.next_encryption_key,
      'm': self.next_mac_key,
      'n': self.nonce
    }

    self.client.put_raw(self.filename, self.client.make_json(obj, self.encryption_key, self.mac_key))

  def get_dirty(self, nonce):
    dirty_blocks = set()
    tl = self
    while True:
      for i in tl.changes:
        dirty_blocks.add(i)

      if nonce == tl.nonce:
        break
      if tl.next_log == None:
        break
      tl = TransactionLog.load(self.client, tl.next_log, tl.next_encryption_key, tl.next_mac_key)

    return dirty_blocks

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
    ct = client.get_raw(filename)
    ptr = client.retrieve_json(ct, encryption_key, mac_key)

    parent = ptr['p']
    parent_enc_key = ptr['e']
    parent_mac_key = ptr['m']

    return SharePointer(client, filename, encryption_key, mac_key, parent, parent_enc_key, parent_mac_key)

  @staticmethod
  def resolve_load(client, filename, encryption_key, mac_key):
    ct = client.get_raw(filename)
    ptr = client.retrieve_json(ct, encryption_key, mac_key)

    if 's' in ptr:
      return SharePointer.load(client, filename, encryption_key, mac_key)
    return FileDescriptor(client, filename, encryption_key, mac_key)

  @staticmethod
  def from_dict(client, obj):
    return SharePointer.load(client, obj['f'], obj['e'], obj['m'])

  def to_dict(self):
    return {
      's': 1,
      'f': self.filename,
      'e': self.encryption_key,
      'm': self.mac_key
    }

  def save(self):
    obj = {
      's': 1,
      'p': self.parent,
      'e': self.parent_encryption_key,
      'm': self.parent_mac_key
    }
    self.client.put_raw(self.filename, self.client.make_json(obj, self.encryption_key, self.mac_key))

  def resolve(self):
    n = self
    while True:
      n = SharePointer.resolve_load(n.client, n.parent, n.parent_encryption_key, n.parent_mac_key)
      if type(n) == FileDescriptor:
        return n

  def share(self, target):
    ptr_name = self.client.gen_key()
    ptr_enc_key = self.client.gen_key()
    ptr_mac_key = self.client.gen_key()

    ptr = SharePointer(self.client, ptr_name, ptr_enc_key, ptr_mac_key, self.filename, self.encryption_key, self.mac_key)
    ptr.save()
    ptrd = ptr.to_dict()
    return ptrd
