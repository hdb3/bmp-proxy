# -*- coding: utf-8 -*-
import multiprocessing
import socket
import copy
import time
import re
import sys

from logger import init_mp_logger

#from openbmp.api.parsed.message import Message
#from openbmp.api.parsed.message import Router
#from openbmp.api.parsed.message import Collector
#from openbmp.api.parsed.message import MsgBusFields

class Listener(multiprocessing.Process):

    def __init__(self, cfg, forward_queue, log_queue):
        """ Constructor

            :param cfg:             Configuration dictionary
            :param forward_queue:   Output for BMP raw message forwarding
            :param log_queue:       Logging queue - sync logging
        """
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

        # wait for config to load
        while not self.stopped():
            if self._cfg and 'proxy' in self._cfg:
                break


        try:

            proxy_port = self._cfg['proxy']['proxy_port']
            self.LOG.info("listening to %d " % proxy_port)

            rcvsock = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
            rcvsock.bind(('', proxy_port))
            #rcvsock.bind(('', 5001))
            rcvsock.listen(1)
            while not self.stopped():
                (clientsocket, address) = rcvsock.accept()
                print("connection received from %s " % address)
                while not self.stopped():
                    msg = clientsocket.recv(1,0)
                    print("msg received with length %d " % len(msg))
                    if 0 == len(msg):
                        break
                    else:
                        self.process_msg(m)
                print("%s disconnected " % address)

            prev_ts = time.time()

        except KeyboardInterrupt:
            pass

        self.LOG.info("consumer stopped")

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

    def process_msg(self, msg):
            pass
