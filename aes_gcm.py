from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import pprint
from binascii import hexlify
from typing import Tuple

def nonce_info( cipher )-> Tuple[ bytes, int ]:
  """returns nonce value and nonce length """
  ## BEGIN CODE TO BE CHANGED'
  nonce = cipher.nonce
  nonce_len = len(nonce)
  ## END CODE TO BE CHANGED
  return nonce, nonce_len 

print( "================================================" )
print( "====== Alice and Bob Secure Communication ======" )
print( "================================================" )

## secret key shared by Alice and Bob
key = get_random_bytes(16)

## Alice
alice_plaintext = b"secret"
print("Alice plaintext is: %s"%alice_plaintext)
##    - 1. initilaization of the cipher
alice_cipher = AES.new(key, AES.MODE_GCM,\
                       nonce=None, mac_len=16)
##    - 2. encryption, authentication
ciphertext, icv = \
  alice_cipher.encrypt_and_digest(alice_plaintext)

print( "The encrypted message sent by Alice to Bob is:" )
print( f"    - ciphertext: {hexlify( ciphertext, sep=' ' )}" ) 
print( f"    - icv: {hexlify(icv, sep=' ' )}" )
nonce, nonce_len = nonce_info( alice_cipher )
print( f"    - nonce [{nonce_len} bytes ]: {hexlify( nonce, sep=' ' )}" )

## Bob
bob_cipher = AES.new(key, AES.MODE_GCM,\
                     nonce=nonce,\
                     mac_len=16)

bob_plaintext = \
  bob_cipher.decrypt_and_verify(ciphertext, icv)
print("Bob plaintext is: %s"%bob_plaintext)

## secret key shared by Alice and Bob
key = b'\xf1\x6a\x93\x0f\x52\xa1\x9b\xbe\x07\x1c\x6d\x44\xb4\x24\xf3\x03'
nonce_dict = {
  'nonce_0': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', \
  'nonce_1': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', \
  'nonce_2': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01', \
  'nonce_3': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' }

nonce_dict_2= {
  'nonce_0': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', \
  'nonce_1': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' }
clear_text = b"secret"

def encrypt_and_digest( key:bytes, nonce_dict:dict, clear_text:bytes ) -> dict:
  """ return a dictionary that associates to any nonce label a uplet 
      ( nonce, cipher_text, icv ) corresponding to the cipher_text and icv 
      of the encrypted clear_text
  """
  output_dict = {}
  ## BEGIN CODE TO BE CHANGED
  for k in nonce_dict:
    cipher = AES.new(key, AES.MODE_GCM,\
                       nonce=nonce_dict.get(k), mac_len=16)
    ciphertext, icv = \
      cipher.encrypt_and_digest(clear_text)
    output_dict[k]= (nonce_dict.get(k),ciphertext,icv)
  ## END CODE TO BE CHANGED
  return output_dict


pprint.pprint(encrypt_and_digest(key,nonce_dict,clear_text))


