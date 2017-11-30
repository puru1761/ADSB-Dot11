#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, hexdump, sniff, send
import sys
import argparse
import json
from logs.logger import log
import threading
import time
from ADSB.ADSB_lib import ADSB_SDR_Thread, ADSB_MSG

## This is a testing script for our library
if __name__=="__main__":

    main_page = "\033[94m[X]\033[0m ADS-B Tranceiver over WiFi \033[94m[X]\033[0m\n"

    parser = argparse.ArgumentParser(description=main_page, epilog="\n\033[93m[*]\033[0m Author: 0xBADB01\n\n")
    
    parser.add_argument('-m', '--mode', help='Mode: This can be "recv" or "send" (Default is recv)', default="recv", required=True)
    parser.add_argument('-i', '--interface', help='Name of the interface to be used', required=True)

    arguments = parser.parse_args()

    if arguments.mode == "send":
        
        sdr = ADSB_SDR_Thread(arguments.mode, arguments.interface)
        even_msg, odd_msg = ADSB_MSG().create("0xABCDEF", 12.34, 56.78, 9999.0)
        sdr.updateMsg(even_msg, odd_msg)

        sdr.start()
        time.sleep(2)
        sdr.stop()
        
        sdr = ADSB_SDR_Thread(arguments.mode, arguments.interface)
        even_msg, odd_msg = ADSB_MSG().create("0xABCDEF", 34.56, 67.89, 9999.0)
        sdr.updateMsg(even_msg, odd_msg)
        sdr.start()
        time.sleep(2)
        sdr.stop()
    
    else:

        sdr = ADSB_SDR_Thread(arguments.mode, arguments.interface)
        sdr.start()
        time.sleep(10)
        sdr.stop()
