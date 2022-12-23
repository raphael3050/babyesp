from construct.core import *
from construct.lib import *
from binascii import hexlify
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


## AES_GCM_16_IIV related shared context between 
## Alice and Bob.
key = b'\xf1\x6a\x93\x0f\x52\xa1\x9b\xbe\x07\x1c\x6d\x44\xb4\x24\xf3\x03'
mac_len=16
ext_seq_num_flag = False
seq_num_counter = 5
salt = b'\xf7\xca\x79\xfa'



def ciphers_obj( key:bytes, mac_len:int, ext_seq_num_flag:bool, seq_num_counter:int, salt:bytes ):
  """ returns the cipher object for AES_GCM """

  
  IIV_Nonce = Struct(
    "salt" / Bytes(4),
    "iv" / IfThenElse(this._.ext_seq_num_flag,
      Struct( "seq_num_counter" / Int64ub),
      Struct( "zero" / Const(b'\x00\x00\x00\x00'),
              "seq_num_counter" / Int32ub)
      )
  )

    ## defining the structure
  nonce = { 'salt' : salt, \
            'iv' : {'seq_num_counter' : seq_num_counter } }
  ## converting structure to binary
  byte_nonce = IIV_Nonce.build(\
                   nonce, 
                   ext_seq_num_flag=ext_seq_num_flag)

  return AES.new(key, AES.MODE_GCM,nonce=byte_nonce,mac_len=mac_len)



## Alice
alice_plaintext = b"yet another secret"
print("Alice plaintext is: %s"%alice_plaintext)
alice_cipher = ciphers_obj(key,mac_len,ext_seq_num_flag,seq_num_counter,salt)
## encryption, authentication
ciphertext, icv =\
  alice_cipher.encrypt_and_digest(alice_plaintext)
nonce = alice_cipher.nonce
print("The encrypted message sent by Alice to Bob is:")
print(" - (nonce [%s]: %s,"%(len(nonce), 
                             hexlify(nonce)))
print(" - ciphertext: %s"%hexlify(ciphertext))
print("icv[%s]: %s"%(len(icv), hexlify(icv)))


## Bob
bob_cipher = AES.new(key, AES.MODE_GCM,\
                     nonce=nonce, mac_len=mac_len)
### verification, decryption
bob_plaintext = \
  bob_cipher.decrypt_and_verify(ciphertext, icv)
print("Bob plaintext is: %s"%bob_plaintext)

