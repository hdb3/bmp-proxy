# bmpparse.py
#
# take a message which is allegedly BMP and parse it into an object wih plausible attributes
#

import struct
import sys
from bgpparse import *

BMP_Route_Monitoring = 0
BMP_Statistics_Report = 1
BMP_Peer_Down_Notification = 2
BMP_Peer_Up_Notification = 3
BMP_Initiation_Message = 4
BMP_Termination_Message = 5
BMP_Route_Mirroring_Message = 6

class BMP_message:

    def __init__(self,msg):
        # parse the common header (CH)
        self.version  = struct.unpack_from('!B', msg, offset=0)[0]
        assert 3 == self.version
        self.length   = struct.unpack_from('!I', msg, offset=1)[0]
        self.msg_type = struct.unpack_from('!B', msg, offset=5)[0]
        msg_len  = len(msg)
        assert msg_len >= self.length


        if 6 < self.msg_type:
            sys.stderr.write("msg_type out of range %d" % self.msg_type)
            ## sys.exit()
            return None

        if (self.msg_type == BMP_Initiation_Message or self.msg_type == BMP_Termination_Message):
            pass # there is no PPC header in these messages
        else:
            assert msg_len > 47
            self.bmp_ppc_fixed_hash = hash(msg[6:40])
            self.bmp_ppc_Peer_Type = struct.unpack_from('!B', msg, offset=6)[0]               # 1 byte index 6
            self.bmp_ppc_Peer_Flags = struct.unpack_from('!B', msg, offset=7)[0]              # 1 byte index 7
            self.bmp_ppc_Peer_Distinguisher  = struct.unpack_from('!Q', msg, offset=8)[0]     # 8 bytes index 8
            # 16 byte field to accomodate IPv6, however I assume IPv4 here!
            self.bmp_ppc_Peer_Address = struct.unpack_from('!I', msg, offset=16)[0]           # 16 bytes index 16
            self.bmp_ppc_Peer_AS = struct.unpack_from('!I', msg, offset=32)[0]                # 4 bytes index 32
            self.bmp_ppc_Peer_BGPID = struct.unpack_from('!I', msg, offset=36)[0]             # 4 bytes index 36
            self.bmp_ppc_Timestamp_Seconds = struct.unpack_from('!I', msg, offset=40)[0]      # 4 bytes index 40
            self.bmp_ppc_Timestamp_Microseconds = struct.unpack_from('!I', msg, offset=44)[0] # 4 bytes index 44


        if (self.msg_type == BMP_Route_Monitoring):
            self.bmp_RM_bgp_message = BGP_message(msg[48:])
