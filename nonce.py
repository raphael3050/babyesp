from construct.core import *
from construct.lib import *
from binascii import hexlify
from typing import Tuple



def show_nonce(salt:bytes, seq_num:int, ext_seq:bool) -> Tuple[ bytes, dict ] :
  """shows the nonce in a binary and structure format """

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
            'iv' : {'seq_num_counter' : seq_num } }
  try:
    ## converting structure to binary
    byte_nonce = IIV_Nonce.build(\
                   nonce, 
                   ext_seq_num_flag=ext_seq)
    ## parsing binary to structure 
    struct_nonce = IIV_Nonce.parse(\
                    byte_nonce, 
                    ext_seq_num_flag=ext_seq)

    return byte_nonce, struct_nonce
  except:
    print("\n---")
    print("> ERROR : Unable to generate the nonce")
    print("> Inputs:")
    print(">    - salt: %s"%salt)
    print(">    - sec_num: %s"%seq_num)
    print(">    - ext_seq_flag: %s"%ext_seq)
    print("-----\n")
    return None, None
  

  ## printing the different representations
  print("\n---")
  print("Inputs:")
  print("    - salt: %s"%salt)
  print("    - sec_num: %s"%seq_num)
  print("    - ext_seq_flag: %s"%ext_seq)
  print("Nonce (binary)")
  print("    - nonce [%s bytes]: %s"%(len(byte_nonce),
                                      byte_nonce))
  print("Nonce (structure)")
  print("    - nonce: %s"%struct_nonce)
  print("---\n")

salt = b'\xf7\xca\x79\xfa'
show_nonce(salt,4294967296,False)
