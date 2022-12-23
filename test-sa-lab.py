from sa import SA
from binascii import hexlify

## The SA is instantiated both Alice and Bob
alice_sa = SA()
## AES_GCM_16_IIV related shared context between Alice and Bob
alice_sa.esp_enc_alg = "ENCR_AES_GCM_16_IIV"
alice_sa.esp_enc_key = b'\xf1\x6a\x93\x0f\x52\xa1\x9b\xbe\x07\x1c\x6d\x44\xb4\x24\xf3\x03'
alice_sa.ext_seq_num_flag = False
alice_sa.seq_num_counter = 5

bob_sa = SA()
## AES_GCM_16_IIV related shared context between Alice and Bob
bob_sa.esp_enc_alg = "ENCR_AES_GCM_16_IIV"
bob_sa.esp_enc_key = b'\xf1\x6a\x93\x0f\x52\xa1\x9b\xbe\x07\x1c\x6d\x44\xb4\x24\xf3\x03'
bob_sa.ext_seq_num_flag = False
bob_sa.seq_num_counter = 5


## Alice
alice_plaintext = b"yet another secret"
print("Alice plaintext is: %s"%alice_plaintext)
alice_cipher = alice_sa.ciphers_obj()[0]
## encryption, authentication
ciphertext, icv = \
  alice_cipher.encrypt_and_digest(alice_plaintext)
nonce = alice_cipher.nonce
print("The encrypted message sent by Alice to Bob is:")
print(" - (nonce [%s]: %s,"%(len(nonce), hexlify(nonce)))
print(" - ciphertext: %s"%hexlify(ciphertext))
print("icv[%s]: %s"%(len(icv), hexlify(icv)))


## Bob
bob_cipher = bob_sa.ciphers_obj()[0]
## encryption, authentication
### verification, decryption
bob_plaintext = \
  bob_cipher.decrypt_and_verify(ciphertext, icv)
print("Bob plaintext is: %s"%bob_plaintext)

