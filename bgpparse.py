# bgpparse.py
#
# take a message which is allegedly BGP and parse it into an object wih plausible attributes
#

import struct
import sys
from binascii import hexlify
from ipaddress import ip_address
def eprint(s):
    sys.stderr.write(s+'\n')

BGP_marker = struct.pack('!QQ',0xffffffffffffffff,0xffffffffffffffff)
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4

BGP_TYPE_CODE_ORIGIN = 1
BGP_TYPE_CODE_AS_PATH = 2
BGP_TYPE_CODE_NEXT_HOP = 3
BGP_TYPE_CODE_MULTI_EXIT_DISC = 4
BGP_TYPE_CODE_LOCAL_PREF = 5
BGP_TYPE_CODE_ATOMIC_AGGREGATE = 6
BGP_TYPE_CODE_AGGREGATOR = 7
BGP_Attribute_Flags_Optional = 0x80 # 1 << 7
BGP_Attribute_Flags_Transitive = 0x40 # 1 << 6
BGP_Attribute_Flags_Partial = 0x20 # 1 << 5
BGP_Attribute_Flags_Extended_Length = 0x10 # 1 << 4


class BGP_message:

    def __init__(self,msg):
        self.attribute = {}
        msg_len  = len(msg)
        assert msg_len > 18
        bgp_marker = msg[0:16]
        assert bgp_marker == BGP_marker
        self.bgp_length = struct.unpack_from('!H', msg, offset=16)[0]
        assert self.bgp_length > 18 and self.bgp_length <= msg_len
        self.bgp_type = struct.unpack_from('!B', msg, offset=18)[0]
        assert self.bgp_type > 0 and self.bgp_type < 5

        if self.bgp_type == BGP_UPDATE:
            self.parse_bgp_update(msg[19:])
        elif self.bgp_type == BGP_OPEN:
            self.parse_bgp_open(msg[19:])
        elif self.bgp_type == BGP_NOTIFICATION:
            self.parse_bgp_notification(msg[19:])

    def parse_bgp_open(self,msg):
        self.bgp_open_version = struct.unpack_from('!B', msg, offset=0)[0]
        self.bgp_open_AS = struct.unpack_from('!H', msg, offset=1)[0]
        self.bgp_open_hold_time = struct.unpack_from('!H', msg, offset=3)[0]
        self.bgp_open_bgp_id = struct.unpack_from('!I', msg, offset=5)[0]
        parameter_length = struct.unpack_from('!B', msg, offset=9)[0]
        self.bgp_open_optional_parameters = self.tlv_parse(msg[10:(9+parameter_length)])
        pass

    def tlv_parsemsg(self):
        pass

    def parse_bgp_update(self,msg):
        lm = len(msg)
        withdrawn_routes_length = struct.unpack_from('!H', msg, offset=0)[0]
        assert lm > withdrawn_routes_length + 3
        self.process_withdrawn_routes(msg[2:2+withdrawn_routes_length])
        path_attribute_length = struct.unpack_from('!H', msg, offset=withdrawn_routes_length+2)[0]
        assert lm > withdrawn_routes_length + 3 + path_attribute_length
        self.process_path_attributes(msg[withdrawn_routes_length + 4 : withdrawn_routes_length + 4 + path_attribute_length])
        self.process_NLRI(msg[ withdrawn_routes_length + 4 + path_attribute_length:])

    def process_withdrawn_routes(self,prefix_list):
        self.withdrawn_prefixes = self.get_prefixes(prefix_list)

    def process_NLRI(self,prefix_list):
        self.prefixes = self.get_prefixes(prefix_list)

    def get_prefixes(self,prefix_list):
    # BGP compresses routes by using the minimum number of bytes needed
    # for the prefix length, i.e. a /24 needs 3 bytes but a /8 needs only 1
    # whether the parser or the application should unpack it is a matter of taste
    # however this library should provide the mechanism in either case.
    # For now, it is done early, whilst parsing....

    # implementation note:
    # avoiding the obvious recursive solution given that these lists can be quite long
    # and testing python implementation of optimising tail recursion is not in scope....
        eprint("get_prefixes")
        eprint( hexlify(prefix_list))
        eprint("")
        prefix_list_length = len(prefix_list)
        offset = 0
        prefixes = []
        while offset < prefix_list_length:
            prefix_length = struct.unpack_from('!B', prefix_list, offset=offset)[0]
            if prefix_length > 24:
                prefix_byte_length = 4
            elif prefix_length > 16:
                prefix_byte_length = 3
            elif prefix_length > 8:
                prefix_byte_length = 2
            elif prefix_length > 0:
                prefix_byte_length = 1
            else:
                prefix_byte_length = 0
            eprint( "++ %d:%d:%d" % (offset,prefix_list_length,prefix_byte_length))
            assert prefix_byte_length + offset < prefix_list_length

            prefix = 0
            if prefix_byte_length > 0:
                prefix = struct.unpack_from('!B', prefix_list, offset=offset+1)[0] << 24
            if prefix_byte_length > 1:
                prefix |= struct.unpack_from('!B', prefix_list, offset=offset+2)[0] << 16
            if prefix_byte_length > 2:
                prefix |= struct.unpack_from('!B', prefix_list, offset=offset+3)[0] << 8
            if prefix_byte_length > 3:
                prefix |= struct.unpack_from('!B', prefix_list, offset=offset+4)[0]

            prefixes += [(prefix_length,prefix)]
            eprint( "++ " + hexlify(prefix_list[offset:offset+ 1 + prefix_byte_length]))
            eprint( "++ %d:%s" % (prefix_length,ip_address(prefix)))
            offset += 1 + prefix_byte_length

        return prefixes


    def process_path_attributes(self,attributes):
        self.attributes = self.get_attributes(attributes)
        self.parse_attributes(self.attributes)
        
    def get_attributes(self,attributes):
        if len(attributes) == 0:
            return []
        attr_flags = struct.unpack_from('!B', attributes, offset=0)[0]
        attr_type_code = struct.unpack_from('!B', attributes, offset=1)[0]
        extended_length = bool(attr_flags & BGP_Attribute_Flags_Extended_Length)
        if extended_length:
            length = struct.unpack_from('!H', attributes, offset=1)[0]
            attribute = attributes[3:3+length]
            tail = attributes[3+length:]
        else:
            length = struct.unpack_from('!B', attributes, offset=1)[0]
            attribute = attributes[2:2+length]
            tail = attributes[2+length:]
        return [(attr_flags,attr_type_code,attribute)] + self.get_attributes(tail)


    def parse_attributes(self,attrs):
        if len(attrs) == 0:
            pass
        else:
            self.parse_attribute(attrs[0])
            self.parse_attributes(attrs[1:])


    def parse_attribute(self,(flags,code,attr)):

        def get_path_ases(as_list):
            if len(as_list) < 2:
                return []
            else:
                return [struct.unpack_from('!H', as_list, offset=0)[0]] + get_path_ases(as_list[2:])

        ## assert code > 0 and code <= BGP_TYPE_CODE_AGGREGATOR
        attr_len = len(attr)
        if (code==BGP_TYPE_CODE_ORIGIN):
            assert attr_len == 1
            self.attribute[BGP_TYPE_CODE_ORIGIN] = struct.unpack_from('!B', attr, offset=0)[0]
        elif (code==BGP_TYPE_CODE_AS_PATH):
            path_segment_type = struct.unpack_from('!B', attr, offset=0)[0]
            path_segment_length = struct.unpack_from('!B', attr, offset=1)[0]
            assert attr_len == 2 + 2*path_segment_length
            ases = get_path_ases(attr[2:])
            self.attribute[BGP_TYPE_CODE_AS_PATH] += [(path_segment_type,ases)]
        elif (code==BGP_TYPE_CODE_NEXT_HOP):
            assert attr_len == 4
            self.attribute[BGP_TYPE_CODE_NEXT_HOP] = struct.unpack_from('!I', attr, offset=0)[0]
        elif (code==BGP_TYPE_CODE_MULTI_EXIT_DISC):
            assert attr_len == 4
            self.attribute[BGP_TYPE_CODE_MULTI_EXIT_DISC] = struct.unpack_from('!I', attr, offset=0)[0]
        elif (code==BGP_TYPE_CODE_LOCAL_PREF):
            assert attr_len == 4
            self.attribute[BGP_TYPE_CODE_LOCAL_PREF] = struct.unpack_from('!I', attr, offset=0)[0]
        elif (code==BGP_TYPE_CODE_ATOMIC_AGGREGATE):
            assert attr_len == 4
            self.attribute[BGP_TYPE_CODE_ATOMIC_AGGREGATE] = True
        elif (code==BGP_TYPE_CODE_AGGREGATOR):
            assert attr_len == 6
            self.attribute[BGP_TYPE_CODE_AGGREGATOR] = (struct.unpack_from('!H', attr, offset=0)[0],struct.unpack_from('!I', attr, offset=4)[0])
        else:
            sys.stderr.write("unknown attribute %d" % code)

    def parse_bgp_notification(self,msg):
        pass
