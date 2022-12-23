from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from ipaddress import IPv4Address, IPv6Address

from construct.core import *
from construct.lib import *


IIV_Nonce = Struct(
    "salt" / Bytes(4),
    "iv" / IfThenElse(this._.ext_seq_num_flag,
      Struct( "seq_num_counter" / Int64ub),
      Struct( "zero" / Const(b'\x00\x00\x00\x00'),
              "seq_num_counter" / Int32ub)
      )
)


class Error(Exception):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message
        self.status = None

class UnsupportedEncAlgError(Error):
    """ Unsupported Encryption Algorithm Error
    """
    pass


class SA:
    
    def __init__(self):
        ## RFC4301
        self.sec_param_index = get_random_bytes(4)
        self.seq_num_counter = 0
        self.seq_counter_overflow = True
        self.anti_replay_win = 1
        self.ah_auth_alg = None
        self.ah_auth_key = None
        self.esp_enc_alg = "ENCR_AES_GCM_16_IIV"
        self.esp_enc_key = get_random_bytes(16)
        self.esp_int_alg = None
        self.esp_int_key = None
        self.lifetime_bytes = None 
        self.lifetime_time = None
        self.mode = "tunnel"
        self.tunnel_header = ('::1', '::1')
        self.path_mtu = None
        ## TS from spd
        self.ext_seq_num_flag = True ## we need this to specify the type
                                     ## (32 vs 64 bit of the seq_num)
        self.local_address = "ANY" ## "ANY" or range []
        self.remote_address = "ANY" ## "ANY" or range []
        self.next_layer_proto = "ANY"
        self.local_port = "ANY" ## "ANY" or range
        self.remote_port = "ANY" # or range
        self.salt = b'\xf7\xca\x79\xfa'        

    def show(self):
        print("   - local_address: %s"%self.local_address)
        print("   - remote_address: %s"%self.remote_address)
        print("   - next_layer_proto: %s"%self.next_layer_proto)
        print("   - local_port: %s"%self.local_port)
        print("   - remote_port: %s"%self.remote_port)

    def match_ip(self, ip_range, ip):
        if ip_range == 'ANY':
            return True
        try:
            ip = IPv6Address(Ipv6Address.build(ip))
        except:
            ip = IPv4Address(IpAddress.build(ip))

        try:
            ip_range = [IPv6Address(ip_range[0]), IPv6Address(ip_range[1])]
        except:
            ip_range = [IPv4Address(ip_range[0]), IPv4Address(ip_range[1])]
        if ip_range[0] <= ip <= ip_range[1]:
            return True
        return False

    def match_local_address(self, ip):
        return self.match_ip(self.local_address, ip)

    def match_remote_address(self, ip):
        return self.match_ip(self.remote_address, ip)


    def match_port(self, port_range, port):
        if port_range == 'ANY':
            return True
        if port_range[0] <= int(port) <= port_range[1]:
            return True
        return False

    def match_local_port(self, port):
        return self.match_port(self.local_port, port)

    def match_remote_port(self, port):
        return self.match_port(self.remote_port, port)


    def match_next_layer_proto(self, next_layer_proto):
        if next_layer_proto == 'ANY':
            return True
        if self.next_layer_proto == next_layer_proto:
            return True
        return False

    def match(self, ts):
        if self.match_remote_address(ts['remote_address']) and\
           self.match_local_address(ts['local_address']) and\
           self.match_remote_port(ts['remote_port']) and\
           self.match_local_port(ts['local_port']):
            return True
        return False

    def ciphers_obj(self):
        """ list of necessary ciphers objects

        Returns:
            ciphers (list): the list of necessary cipher objects. With
                AEAD encryption the list has one cipher, otherwise 
                encryption and authentication algorithm are returned.

        """
        if self.esp_enc_alg  == "ENCR_AES_GCM_16_IIV":

            nonce = { 'salt' : self.salt, \
                    'iv' : {'seq_num_counter' : self.seq_num_counter } }
            byte_nonce = IIV_Nonce.build(\
                        nonce, 
                        ext_seq_num_flag=self.ext_seq_num_flag)
            return [ AES.new(self.esp_enc_key,AES.MODE_GCM,nonce=byte_nonce,mac_len=self.icv_len()) ]

        raise UnsupportedEncAlgError(sa.esp_enc_alg, "unsupported") 

    def icv_len(self):
        if self.esp_enc_alg == "ENCR_AES_GCM_16_IIV":
            return int(16)

    def seq_num_counter_len(self):
        return 4

    def sec_param_index_len(self):
        return 4

    def get_seq_num_counter(self, sn_len=None):
        if sn_len == None:
            sn_len = self.seq_num_counter_len()
        if sn_len == 0:
            return b''
        return Int64ub.build(self.seq_num_counter)[-sn_len:]

    def get_sec_param_index(self, spi_len=None):
        if spi_len == None:
            spi_len = self.sec_param_index_len()
        if spi_len == 0:
            return b''
        return self.sec_param_index[-spi_len:]

    def ts_ip_version(self):
        try:
            IPv6Address(self.local_address[0])
            return 6
        except:
            try:
                IPv4Address(self.local_address[0])
                return 4
            except:
                return 6
