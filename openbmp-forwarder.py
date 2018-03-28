#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""OpenBMP forwarder

  Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
  This program and the accompanying materials are made available under the
  terms of the Eclipse Public License v1.0 which accompanies this distribution,
  and is available at http://www.eclipse.org/legal/epl-v10.html

  .. moduleauthor:: Tim Evens <tievens@cisco.com>
"""
import getopt
import sys
import logging
import yaml
import time
import signal

from multiprocessing import Queue, Manager
from logger import LoggerThread
from bmp_consumer import BMPConsumer
from forwarder_bmp import BMPWriter

# Root logger
LOG = None

# Running flag for main process
RUNNING = True

# Default App name
APP_NAME = "openbmp-forwarder"


def signal_handler(signum, frame):
    """ Signal handler to shutdown the program

        :param signum:          Signal number
        :param frame:           Stack
    """
    global RUNNING, LOG

    if LOG:
        LOG.info("Caught signal %d, exiting", signum)
    else:
        print "Caught signal %d, exiting" % signum

    RUNNING = False


def load_config(cfg_filename, LOG):
    """ Load and validate the configuration from YAML

        Some defaults are applied if any settings are missing.

        :param cfg_filename:    Configuration filename to load
        :param LOG:             logger

        :return: Configuration dictionary is returned
    """
    cfg = {}

    try:
        cfg = yaml.load(file(cfg_filename, 'r'))

        # Validate the config and set defaults if undefined
        if 'kafka' in cfg:
            if 'servers' not in cfg['kafka']:
                cfg['kafka']['servers'] = ['localhost:9092']
            if 'client_id' not in cfg['kafka']:
                cfg['kafka']['client_id'] = APP_NAME
            if 'group_id' not in cfg['kafka']:
                cfg['kafka']['group_id'] = APP_NAME
            if 'offset_reset_largest' not in cfg['kafka']:
                cfg['kafka']['offset_reset_largest'] = False

        else:
            cfg['kafka'] = {}
            cfg['kafka']['servers'] = ['localhost:9092']
            cfg['kafka']['client_id'] = APP_NAME
            cfg['kafka']['group_id'] = APP_NAME
            cfg['kafka']['offset_reset_largest'] = False

        if 'collector' in cfg:
            if 'host' not in cfg['collector']:
                if LOG:
                    LOG.error("Configuration is missing 'host' in collector section")
                else:
                    print ("Configuration is missing 'host' in collector section")
                sys.exit(2)

            if 'port' not in cfg['collector']:
                if LOG:
                    LOG.error("Configuration is missing 'port' in collector section, using default of 5000")
                else:
                    print ("Configuration is missing 'port' in collector section, using default of 5000")

                cfg['collector']['port'] = 5000

        else:
            if LOG:
                LOG.error("Configuration is missing 'collector' section.")
            else:
                print ("Configuration is missing 'collector' section.")
            sys.exit(2)

        if 'logging' not in cfg:
            if LOG:
                LOG.error("Configuration is missing 'logging' section.")
            else:
                print ("Configuration is missing 'logging' section.")
            sys.exit(2)

    except (IOError, yaml.YAMLError), e:
        print "Failed to load mapping config file '%s': %r" % (cfg_filename, e)
        if hasattr(e, 'problem_mark'):
            mark = e.problem_mark
            print ("error on line: %s, column: %s" % (mark.line+1, mark.column+1))

        sys.exit(2)

    return cfg


def usage(prog):

    """ Usage - Prints the usage for this program.

        :param prog:  Program name
    """
    print ""
    print "Usage: %s [OPTIONS]" % prog
    print ""

    print "OPTIONS:"
    print "  -h, --help".ljust(30) + "Print this help menu"
    print "  -c, --config".ljust(30) + "Config filename (default is %s/etc/openbmp-forwarder.yml)" % sys.prefix
    print ""


def parse_cmd_args(argv):
    """ Parse commandline arguments and load the configuration file

        Usage is printed and program is terminated if there is an error.

        :param argv:   ARGV as provided by sys.argv.  Arg 0 is the program name

        :returns: Command line arg configuration dictionary
    """
    cfg = {
            'cfg_filename': "bmp-proxy.yml"
            # 'cfg_filename': "%s/etc/%s.yml" % (sys.prefix, APP_NAME)
           }

    try:
        (opts, args) = getopt.getopt(argv[1:], "hc:",
                                       ["help", "config="])

        for o, a in opts:
            if o in ("-h", "--help"):
                usage(argv[0])
                sys.exit(0)

            elif o in ("-c", "--config"):
                cfg['cfg_filename'] = a

            else:
                usage(argv[0])
                sys.exit(1)

    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
        usage(argv[0])
        sys.exit(2)

    return cfg


def main():
    """ Main entry point """
    global LOG, RUNNING

    cmd_cfg = parse_cmd_args(sys.argv)
    cfg = load_config(cmd_cfg['cfg_filename'], LOG)

    # Shared dictionary between processes
    manager = Manager()
    cfg_dict = manager.dict()
    cfg_dict['max_queue_size'] = cfg['max_queue_size']
    cfg_dict['logging'] = cfg['logging']
    cfg_dict['kafka'] = cfg['kafka']
    cfg_dict['collector'] = cfg['collector']

    # Setup signal handers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)

    # Setup the multiprocessing logging queue
    log_queue = Queue()
    thread_logger = LoggerThread(log_queue, cfg_dict['logging'])
    thread_logger.start()

    LOG = logging.getLogger()

    # Use manager queue to ensure no duplicates
    forward_queue = manager.Queue(cfg_dict['max_queue_size'])

    # Start the BMP consumer process
    proc_consumer = BMPConsumer(cfg_dict, forward_queue, log_queue)
    proc_consumer.start()

    # Start the BMP writer process
    proc_writer = BMPWriter(cfg_dict, forward_queue, log_queue)
    proc_writer.start()

    LOG.info("Threads started")

    # Monitor/do something else if needed
    while RUNNING:

        try:
            time.sleep(3)

        except KeyboardInterrupt:
            print "\nStop requested by user"
            RUNNING = False
            break

    proc_consumer.stop()
    time.sleep(1)

    proc_writer.stop()
    time.sleep(1)

    manager.shutdown()

    thread_logger.stop()
    thread_logger.join()

    sys.exit(0)


if __name__ == '__main__':
    main()
