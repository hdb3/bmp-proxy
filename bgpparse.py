# bgpparse.py
#
# take a message which is allegedly BGP and parse it into an object wih plausible attributes
#

import struct

BGP_marker = struct.pack('!QQ',0xffffffffffffffff,0xffffffffffffffff)
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4

class BGP_message:

    def __init__(self,msg):
        msg_len  = len(msg)
        assert msg_len > 18
        bgp_marker = msg[0:16]
        assert bgp_marker == BGP_marker
        self.bgp_length = struct.unpack_from('!H', msg, offset=16)[0]
        assert self.bgp_length > 18 and self.bgp_length <= msg_len
        self.bgp_type = struct.unpack_from('!B', msg, offset=18)[0]
        assert self.bgp_type > 0 and self.bgp_type < 5
