from construct.core import *
from construct.lib import *

from sa import SA, Error


## Teh section to be completed are indicated with
## BEGIN_CODE and END_CODE.

"""

https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
https://construct.readthedocs.io/en/latest/meta.html

"""
NextHeader = Enum(BytesInteger(1),
    IPv4 = 6,
    TCP = 6,
    UDP = 17,
    IPv6 = 41,
    ESP = 50,
    AH = 51,
    NoNxt = 59,
    SCTP = 132
)


Pad = GreedyRange(Byte)

ESPHeader = Struct(
    "sec_param_index" / Bytes(4),
    "seq_num_counter" / Bytes(4),
)

ClearTextESPPayload = Struct(
     "data" / Bytes(this._.data_len),
     "pad" / Bytes(this._.pad_len),
#     "pad_len" / Rebuild( Int8ub, len_(this.pad)),
     "pad_len" / Int8ub,
     "next_header" / NextHeader,
     "integrity" / Check(this.pad_len == len_(this.pad)),
)

ClearTextESP = Struct(
Embedded(ESPHeader),
Embedded(ClearTextESPPayload)
)

EncryptedESPPayload = Struct(
    "encrypted_payload" / Bytes(this._.encrypted_payload_len),
    "icv" / Bytes(this._.icv_len)
)

EncryptedESP = Struct(
Embedded(ESPHeader),
Embedded(EncryptedESPPayload)
)

""" class ESP that implements encapsulation / decapsulation of ESP packets """

class ESP:
    def __init__(self, sa):
        self.sa = sa

    def encrypt_and_digest(self, bytes_data):
        """ encrypts bytes_data and returns encrypted_payload and icv

        Args:
            bytes_data (bytes): data to be encrypted

        Returns:
            encrypted_payload (bytes): the corresponding encrypted data
            icv, the icv

        This function initiates a cipher object for every packet. In
            fact, the object has to be instantiated for each nonce. In
            addition, encryption and decryption is not expected to be
            performed by different nodes, so different objects.
        """
        ciphers = self.sa.ciphers_obj()
        if len(ciphers) == 1:
            return ciphers[0].encrypt_and_digest(bytes_data)

    def decrypt_and_verify(self, payload):
        """ decrypt data from encrypted_dats and icv

        Args:
            payload (dict): with encrypted_payload and icv. The ESP payload
                or ESP packet can be used.
        Returns:
            data (bytes): the decrypted data.
        """

        ciphers = self.sa.ciphers_obj()
        if len(ciphers) == 1: #AEAD
            data = ciphers[0].decrypt_and_verify(\
                   payload['encrypted_payload'], payload['icv'])
        return data


    def pad(self, data_len):
        """ returns padding bytes """
        ##padding_length = 8 - (data_len % 8)

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

    def pack(self, data, pad_len=None, next_header="IPv6"):
        """ Generates an ESP encrypted packet

        Args:
            data (bytes): the data field of the ESP packet
            pad_len (int): the pad length (<255). Default value is None
                so pad_len is computed as the minimal value that provides
                32 bit alignment
        Returns:
            encrypted_pkt (dict): the dictionary representing the ESP
                packet: {'sec_param_index':spi, 'seq_num_counter':sn,\
                          'encrypted_payload':ep, 'icv':icv}

        """

        pad = self.pad(len(data))
        byte_payload = ClearTextESPPayload.build(
                       {'data':data, 'pad':pad, 'pad_len':len(pad), \
                        'next_header':next_header}, data_len=len(data), pad_len=len(pad))
        encrypted_payload, icv = self.encrypt_and_digest(byte_payload)
        return {'sec_param_index':self.sa.get_sec_param_index(),\
                'seq_num_counter':self.sa.get_seq_num_counter(),\
                'encrypted_payload':encrypted_payload, 'icv':icv}

    def unpack(self, encrypted_pkt):
        """ Returns the clear text data of an ESP encrypted packet

        unpack reverses the pack function. In fact encrypted_pkt may be
        limited to a dictionary with the keys 'encrypted_payload' and
        'icv' as only these keys are used.

        Args:
            encrypted_pkt (dict): a dictionary with keys:
                'encrypted_payload' and 'icv'
        Returns:
            data (bytes): the data in clear text.

        """
        byte_payload = self.decrypt_and_verify( \
                           encrypted_pkt)
        pad_len = byte_payload[-2]
        data_len = len(byte_payload) - 2 - pad_len
        payload = ClearTextESPPayload.parse(byte_payload, pad_len=pad_len,\
                                            data_len=data_len)
        return payload


    def to_bytes(self, encrypted_esp_pkt):
        """ Converts an encrypted ESP packet structure to bytes

        Args:
            encrypted_esp_pkt (dict): structure of an ESP packet

        Returns:
           byte_encrypted_Esp_pkt (bytes): byte stream corresponding to
               the ESP packet

        Todo:
            include the length computation in the structure.
        """

        encrypted_payload_len = len(encrypted_esp_pkt['encrypted_payload'])
        return EncryptedESP.build(encrypted_esp_pkt,\
                   encrypted_payload_len=encrypted_payload_len, \
                   icv_len=self.sa.icv_len())


    def from_bytes(self, byte_encrypted_esp_pkt):
        """ Converts an encrypted ESP packet from bytes to structure

        Converts (encrypted) ESP packet from an byte representation
        to a dict structure

        Args:
            byte_encrypted_esp_pkt (bytes): byte representation of an
                encrypted ESP packet

        Returns:
            encrypted_esp_pkt (dict): structure representation of an
                encrypted ESP packet.

        Todo:
            include the length computation in the structure.
        """
        encrypted_payload_len = len(byte_encrypted_esp_pkt) - 8 - \
                                self.sa.icv_len()
        return EncryptedESP.parse(byte_encrypted_esp_pkt, \
                   encrypted_payload_len=encrypted_payload_len, \
                   icv_len=self.sa.icv_len())



## Shared SA between Alice and Bob

sa = SA()
esp = ESP(sa)

## Alice inner packet
print("-- Alice Data payload")
alice_inner_ip_pkt = b'inner_ip6_packet'
print("data payload: %s"%alice_inner_ip_pkt) 

## Encapsulation of the inner packet in to ESP 
print("-- Alice Clear text ESP payload")
pad = esp.pad(len(alice_inner_ip_pkt))

### Complete the structure associated to the ESP
### payload with the appropriated expressions for
### XXX. Express pad_len as a function of pad. 
### next_header should be given the value that 
### describes data as an IPv6 packet.  
alice_clear_text_esp = {'data':alice_inner_ip_pkt,\
                        'pad':pad,\
                        'pad_len': len(pad), \
                        'next_header':41}
print(alice_clear_text_esp)

print("-- Alice Encrypting clear text" +\
      "and concatenating with ESP header")
alice_esp = esp.pack(alice_inner_ip_pkt)
print(alice_esp)

print("-- Alice sending ESP in byte format:")
bytes_esp = esp.to_bytes(alice_esp)
print("  esp: %s"%hexlify(bytes_esp))

print("-- Bob receives the packet")
### Complete the code so that bytes_esp which has
### a byte format is converted into a structure 
### such as a dictionary. The returned dictionary 
### is designated as bob_esp. 
#BEGIN_CODE
bob_esp = esp.from_bytes(bytes_esp)
#END_CODE
print(bob_esp)

print("-- Bob decrypts the encrypted part")
encrypted_esp = {\
  'encrypted_payload': bob_esp['encrypted_payload'], \
  'icv': bob_esp['icv']}

### Complete the code with the function that takes 
### the encrypted_esp structure proceed to the 
### decryption and returns the structure associated 
### to the clear text esp. This structure is 
### designated as bob_clear_text_esp. The data
### alice_inner_ip_pkt is read from this structure. 

bob_clear_text_esp = esp.unpack(encrypted_esp)
print(bob_clear_text_esp)

print("-- Bob extracts the Data payload")
print(bob_clear_text_esp['data'])


print("The short version would be:")
print("    - pack:%s"%esp.pack(alice_inner_ip_pkt))
print("    - unpack:%s"\
  %esp.unpack(esp.pack(alice_inner_ip_pkt)))





