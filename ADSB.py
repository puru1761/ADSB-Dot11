#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, hexdump, sniff
import sys
import argparse
from logs.logger import log 

class ADSB_SDR():

    def __init__(self):
        pass

    def startBroadcast(self, interface, ssid):
        
        dot11 = Dot11(type=2, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
        beacon = Dot11Beacon(cap='ESS')
        essid = Dot11Elt(ID ='SSID', info=ssid, len=len(ssid))
        
        rsn = Dot11Elt(ID='RSNinfo', info=(
            '\xAD\xDE'))

        frame = RadioTap()/dot11/beacon/essid/rsn

        log.info("Beacon Frame created with SSID: '"+ssid+"'")
        log.info("Transmitting Beacon through interface '"+interface+"'")
        
        log.success("Broadcast Started")

        sendp(frame, iface=interface, inter=0.10, loop=1, verbose=False)

    
    def recvBroadcast(self, interface):

        sniff(iface=interface, prn=self.filterPackets)

    
    def filterPackets(self, packet):

        if packet.haslayer(Dot11) and packet.type == 2 and packet.subtype == 8 and packet.addr2 == '22:22:22:22:22:22':

            print packet.show()


if __name__=="__main__":

    main_page = "\033[94m[X]\033[0m ADS-B Tranceiver over WiFi \033[94m[X]\033[0m\n"

    parser = argparse.ArgumentParser(description=main_page, epilog="\n\033[93m[*]\033[0m Author: 0xBADB01\n\n")
    
    parser.add_argument('-m', '--mode', help='Mode: This can be "recv" or "send" (Default is recv)', default="recv", required=True)
    parser.add_argument('-i', '--interface', help='Name of the interface to be used', required=True)
    parser.add_argument('--ssid', help='Your ADS-B Broadcast name', default="DRONE")

    args = parser.parse_args()

    sdr = ADSB_SDR()

    if args.mode == 'recv':
        sdr.recvBroadcast(args.interface)

    elif args.mode == 'send':
        sdr.startBroadcast(args.interface, args.ssid)

    else:
        parser.print_help()
