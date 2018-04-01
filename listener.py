# -*- coding: utf-8 -*-
import multiprocessing
import socket
import copy
import time
import sys
from bgpparse import *
from bmpparse import *

from logger import init_mp_logger

def eprint(s):
   sys.stderr.write(s+'\n')

MAXM = 0x1000000

class Listener(multiprocessing.Process):

    def __init__(self, cfg, forward_queue, log_queue):
        multiprocessing.Process.__init__(self)
        self._stop = multiprocessing.Event()

        self._cfg = cfg
        self._fwd_queue = forward_queue
        self._log_queue = log_queue
        self.LOG = None

    def run(self):
        """ Override """
        self.LOG = init_mp_logger("listener", self._log_queue)
        self.LOG.info("Running listener")

        if not ( self._cfg and 'listener' in self._cfg):
            sys.exit("could not load listener configuration")

        try:

            port = self._cfg['listener']['port']
            self.LOG.info("listening to %d " % port)

            rcvsock = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
            rcvsock.bind(('', port))
            rcvsock.listen(1)
            max_msg_len = 0
            while not self.stopped():
                (clientsocket, address) = rcvsock.accept()
                eprint("connection received from %s:%d " % address)
                while not self.stopped():
                    msg = clientsocket.recv(MAXM) # BGP max message size is 4096......
                    if len(msg) > max_msg_len:
                        max_msg_len = len(msg)
                        sys.stderr.write("*****! msg received with length %d " % len(msg))
                    assert MAXM > len(msg)
                    if 0 == len(msg):
                        break
                    else:
                        self.process_msg(msg)
                eprint("disconnected")

            prev_ts = time.time()

        except KeyboardInterrupt:
            pass

        self.LOG.info("consumer stopped")

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

    def process_msg(self, raw_msg):
        bmpmsgs = get_BMP_messages(raw_msg)
        for bmpmsg in bmpmsgs:
            if bmpmsg.msg_type == BMP_Statistics_Report:
                eprint("-- BMP stats report rcvd, length %d" % bmpmsg.length)
            elif bmpmsg.msg_type == BMP_Route_Monitoring:
                bgpmsg = bmpmsg.bmp_RM_bgp_message
                ## eprint("-- BMP RM rcvd, length %d" % bmpmsg.length)
            else:
                eprint("-- BMP non RM rcvd, BmP msg type was %d, length %d" % (bmpmsg.msg_type,bmpmsg.length))
