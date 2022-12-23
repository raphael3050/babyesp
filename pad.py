from construct.core import *
from construct.lib import *

def pad( data_len ):
  """ return the Padding field 

  Args:
    data_len: the length of the Data Payload 
  """
  ### Complete the code so it returns the necessary 
  ### padding bytes for an ESP packet. The padding 
  ### bytes are derived from data_len the length 
  ### expressed in number of bytes of the Data 
  ### Payload 

  ##BEGIN_CODE
  padding_bytes = b'\x01'
  pad_len = len(padding_bytes)
  i = 2
  while(((data_len + 2 + pad_len) % 4) != 0):
      padding_bytes = padding_bytes + bytes([i])
      pad_len = len(padding_bytes)
      i = i+1
  return padding_bytes
  ##END_CODE

