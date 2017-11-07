#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, hexdump, sniff, send
import sys
import argparse
import json
from logs.logger import log

class ADSB_MSG():

    def __init__(self):

        self.msg = {
                    "DF":"", 
                    "CA":"", 
                    "ICAO":"", 
                    "DATA":{"DATA":"", "TYPE":""}, 
                    "PARITY":""
                    }


    def createIdentMsg(self, DF, CA, ICAO, data, parity):
        
        self.msg["DF"] = DF
        self.msg["CA"] = CA
        self.msg["ICAO"] = ICAO
        self.msg["DATA"]["DATA"] = data
        self.msg["DATA"]["TYPE"] = "1"
        self.msg["PARITY"] = parity

        return json.dumps(self.msg)

    def createPositionMsg_Baro(self, DF, CA, ICAO, data, parity):
        pass

    def createPositionMsg_surface(self, DF, CA, ICAO, data, parity):
        pass

    def createPositionMsg_GNSS(self, DF, CA, ICAO, data, parity):
        pass

    def createVelocityMessage(self, DF, CA, ICAO, data, parity):
        pass

class ADSB_SDR():

    def __init__(self):
        pass

    def startBroadcast(self, interface, ssid, msg):
        
        dot11 = Dot11(type=2, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
        beacon = Dot11Beacon(cap='ESS')
        essid = Dot11Elt(ID ='SSID', info=ssid, len=len(ssid))
        
        adsb = ADSB_MSG()

        msg = adsb.createIdentMsg("17", "5", "0xABCDEF", "XXXXXX", "567890")
        rsn = Dot11Elt(ID='RSNinfo', info=(msg))

        frame = RadioTap()/dot11/beacon/essid/rsn

        log.info("Transmitting Beacon through interface '"+interface+"'")
        
        log.success("Broadcast Started")

        sendp(frame, iface=interface, inter=0.10, loop=1, verbose=False)


    
    def recvBroadcast(self, interface):

        sniff(iface=interface, prn=self.filterPackets)

    
    def filterPackets(self, pkt):

        # Contains hardcoded address "22:22:22:22:22:22". Need to implement Additional logic

        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.subtype == 8 and pkt.addr2 == "22:22:22:22:22:22":

            if "ADSB" in pkt.load:

                adsb_packet = json.loads(pkt.load[15:])
                
                log.success("ADS-B Packet received!")
                log.info("DF -> "+adsb_packet["DF"])
                log.info("CA -> "+adsb_packet["CA"])
                log.info("ICAO -> "+adsb_packet["ICAO"])
                log.info("DATA ->"+adsb_packet["DATA"]["DATA"])
                log.info("TYPE CODE -> "+adsb_packet["DATA"]["TYPE"])
                log.info("PARITY -> "+adsb_packet["PARITY"])
        


if __name__=="__main__":

    main_page = "\033[94m[X]\033[0m ADS-B Tranceiver over WiFi \033[94m[X]\033[0m\n"

    parser = argparse.ArgumentParser(description=main_page, epilog="\n\033[93m[*]\033[0m Author: 0xBADB01\n\n")
    
    parser.add_argument('-m', '--mode', help='Mode: This can be "recv" or "send" (Default is recv)', default="recv", required=True)
    parser.add_argument('-i', '--interface', help='Name of the interface to be used', required=True)

    args = parser.parse_args()

    sdr = ADSB_SDR()

    if args.mode == 'recv':
        sdr.recvBroadcast(args.interface)

    elif args.mode == 'send':

        # Example usage with an identification message. Meant to be used as a library

        adsb = ADSB_MSG()
        msg = adsb.createIdentMsg("17", "5", "ABCDEF", "XXXXXX", "567890")
        sdr.startBroadcast(args.interface, "ADSB", msg)


    else:
        parser.print_help()
