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

class ADSB_MSG():

    def __init__(self):

        self.msg = {
                    "DF":"", 
                    "CA":"", 
                    "ICAO":"", 
                    "DATA":{"DATA":"", "TYPE":""}, 
                    "PARITY":""
                    }


    def IdentMsg(self, DF, CA, ICAO, data, parity):
        
        self.msg["DF"] = DF
        self.msg["CA"] = CA
        self.msg["ICAO"] = ICAO
        self.msg["DATA"]["DATA"] = data
        self.msg["DATA"]["TYPE"] = "1"
        self.msg["PARITY"] = parity

        return json.dumps(self.msg)

    def PositionMsg_Baro(self, DF, CA, ICAO, data, parity):
        self.msg["DF"] = DF
        self.msg["CA"] = CA
        self.msg["ICAO"] = ICAO
        self.msg["DATA"]["DATA"] = data
        self.msg["DATA"]["TYPE"] = "9"
        self.msg["PARITY"] = parity

        return json.dumps(self.msg)

    def PositionMsg_surface(self, DF, CA, ICAO, data, parity):
        self.msg["DF"] = DF
        self.msg["CA"] = CA
        self.msg["ICAO"] = ICAO
        self.msg["DATA"]["DATA"] = data
        self.msg["DATA"]["TYPE"] = "5"
        self.msg["PARITY"] = parity

        return json.dumps(self.msg)

    def PositionMsg_GNSS(self, DF, CA, ICAO, data, parity):
        self.msg["DF"] = DF
        self.msg["CA"] = CA
        self.msg["ICAO"] = ICAO
        self.msg["DATA"]["DATA"] = data
        self.msg["DATA"]["TYPE"] = "20"
        self.msg["PARITY"] = parity

        return json.dumps(self.msg)

    def VelocityMsg(self, DF, CA, ICAO, data, parity):
        self.msg["DF"] = DF
        self.msg["CA"] = CA
        self.msg["ICAO"] = ICAO
        self.msg["DATA"]["DATA"] = data
        self.msg["DATA"]["TYPE"] = "19"
        self.msg["PARITY"] = parity

        return json.dumps(self.msg)

class ADSB_SDR_Thread(threading.Thread):

    def __init__(self, mode, interface):
        threading.Thread.__init__(self)

        self.mode = mode
        self.interface = interface
        self.msg = ADSB_MSG()
        self.ADSB_Packets = []

        if self.mode == "send":

            log.info("Transmitting Beacon through interface '"+interface+"'")
            log.success("Broadcast Started")
        
        self.stopFlag = threading.Event()

    def stop(self):
        self.stopFlag.set()

    def is_stopped(self, dummy):
        return self.stopFlag.is_set()

    def run(self):
        
        while not self.is_stopped("Test"):
            if self.mode == "send":
                time.sleep(0.1)
                self.startBroadcast(self.interface, "ADSB", self.msg)
            elif self.mode == "recv":
                self.recvBroadcast(self.interface)

    def startBroadcast(self, interface, ssid, msg):
        
        dot11 = Dot11(type=2, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
        beacon = Dot11Beacon(cap='ESS')
        essid = Dot11Elt(ID ='SSID', info=ssid, len=len(ssid))
        
        adsb = ADSB_MSG()

        rsn = Dot11Elt(ID='RSNinfo', info=(msg))

        frame = RadioTap()/dot11/beacon/essid/rsn


        sendp(frame, iface=interface, inter=0.10, loop=0, verbose=False)


    def updateMSG(self, msg):
        self.msg = msg
    
    def recvBroadcast(self, interface):

        sniff(iface=interface, prn=self.filterPackets, stop_filter=self.is_stopped)

    
    def filterPackets(self, pkt):

        # Contains hardcoded address "22:22:22:22:22:22". Need to implement Additional logic

        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.subtype == 8 and pkt.addr2 == "22:22:22:22:22:22":

            if "ADSB" in pkt.load:

                self.ADSB_Packets.append(json.loads(pkt.load[15:]))
               
                """
                adsb_packet = json.loads(pkt.load[15:])
                log.success("ADS-B Packet received!")
                log.info("DF -> "+adsb_packet["DF"])
                log.info("CA -> "+adsb_packet["CA"])
                log.info("ICAO -> "+adsb_packet["ICAO"])
                log.info("DATA ->"+adsb_packet["DATA"]["DATA"])
                log.info("TYPE CODE -> "+adsb_packet["DATA"]["TYPE"])
                log.info("PARITY -> "+adsb_packet["PARITY"])
                """

## This is a testing script for our library
if __name__=="__main__":

    main_page = "\033[94m[X]\033[0m ADS-B Tranceiver over WiFi \033[94m[X]\033[0m\n"

    parser = argparse.ArgumentParser(description=main_page, epilog="\n\033[93m[*]\033[0m Author: 0xBADB01\n\n")
    
    parser.add_argument('-m', '--mode', help='Mode: This can be "recv" or "send" (Default is recv)', default="recv", required=True)
    parser.add_argument('-i', '--interface', help='Name of the interface to be used', required=True)

    arguments = parser.parse_args()

    if arguments.mode == "send":
        
        sdr = ADSB_SDR_Thread(arguments.mode, arguments.interface)
        sdr.updateMSG(ADSB_MSG().IdentMsg("5", "5", "5", "5", "5"))

        sdr.start()
        time.sleep(2)
        sdr.stop()
        
        sdr = ADSB_SDR_Thread(arguments.mode, arguments.interface)
        sdr.updateMSG(ADSB_MSG().VelocityMsg("8","8","8","8","8"))
        sdr.start()
        time.sleep(2)
        sdr.stop()
    
    else:

        sdr = ADSB_SDR_Thread(arguments.mode, arguments.interface)
        sdr.start()
        time.sleep(10)
        print sdr.ADSB_Packets
        sdr.stop()
