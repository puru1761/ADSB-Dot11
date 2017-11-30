import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, hexdump, sniff, send
import sys
import argparse
import json
from logs.logger import log
import threading
import time
import pyModeS as pms
import ADSB_Encoder

class ADSB_MSG():

    def __init__(self):

        self.even_msg = ''
        self.odd_msg = ''

    def create(self, icao, latitude, longitude, altitude):

        self.even_msg, self.odd_msg = ADSB_Encoder.create_message(icao, latitude, longitude, altitude)

        return self.even_msg, self.odd_msg



class ADSB_SDR_Thread(threading.Thread):

    def __init__(self, mode, interface):
        threading.Thread.__init__(self)

        self.mode = mode
        self.interface = interface
        self.odd_msg = ''
        self.even_msg = ''
        self.msg = ''
        self.position = ()

        if self.mode == "send":

            log.info("Transmitting Beacon through interface '"+interface+"'")
            log.success("Broadcast Started")
        
        self.stopFlag = threading.Event()
        self.pos_change_flag = threading.Event()

    def stop(self):
        self.stopFlag.set()

    def is_stopped(self, dummy):
        return self.stopFlag.is_set()

    def run(self):
        
        while not self.is_stopped("Test"):
            if self.mode == "send":
                time.sleep(0.5)

                if self.even_msg and self.odd_msg: 
                    self.startBroadcast(self.interface, "ADSB", self.even_msg)
                    self.startBroadcast(self.interface, "ADSB", self.odd_msg)
                else:
                    log.err("Please Set the message first!")

            elif self.mode == "recv":
                self.recvBroadcast(self.interface)

    def change_pos(self):
        self.pos_change_flag.set()

    def is_pos_changed(self):
        return self.pos_change_flag.is_set()

    def startBroadcast(self, interface, ssid, msg):
        
        dot11 = Dot11(type=2, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
        beacon = Dot11Beacon(cap='ESS')
        essid = Dot11Elt(ID ='SSID', info=ssid, len=len(ssid))
        
        adsb = ADSB_MSG()

        rsn = Dot11Elt(ID='RSNinfo', info=(msg))

        frame = RadioTap()/dot11/beacon/essid/rsn


        sendp(frame, iface=interface, inter=0.10, loop=0, verbose=False)


    def updateMsg(self, even_msg, odd_msg):
        self.even_msg = ''.join(format(x, '02x') for x in even_msg)
        self.odd_msg = ''.join(format(y, '02x') for y in odd_msg)
    
    def recvBroadcast(self, interface):

        sniff(iface=interface, prn=self.filterPackets, stop_filter=self.is_stopped)

    
    def filterPackets(self, pkt):

        # Contains hardcoded address "22:22:22:22:22:22". Need to implement Additional logic

        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.subtype == 8 and pkt.addr2 == "22:22:22:22:22:22":

            if "ADSB" in pkt.load:

                msg = pkt.load[15:]
                signal_bits = pms.hex2bin(msg)

                type_code = int(signal_bits[32:37], 2)

                if type_code == 11:
                    position = self.calcPosition(msg)
                    if position and position != self.position:
                        self.position = position
                        print self.position

    def calcPosition(self, data):
       
        signal_bits = pms.hex2bin(data)
        message = signal_bits[32:]

        if message[21] == '0':
            self.even_msg = data
        elif message[21] == '1':
            self.odd_msg = data

        if self.even_msg and self.odd_msg:

            altitude = pms.adsb.altitude(self.even_msg)

            latitude, longitude = pms.adsb.airborne_position(self.even_msg, self.odd_msg, 0, 0)
            self.even_msg = '' 
            self.odd_msg = ''

            return (latitude, longitude, altitude)
            
        
