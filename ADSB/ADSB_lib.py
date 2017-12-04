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
from datetime import datetime

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
        self.position = []

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

                adsb_message = {"even":"", "odd":""}
                if self.even_msg and self.odd_msg:
                    adsb_message["even"] = self.even_msg
                    adsb_message["odd"] = self.odd_msg
                    self.startBroadcast(self.interface, "ADSB", json.dumps(adsb_message))
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

                msg = json.loads(pkt.load[15:])
                signal_bits_even = pms.hex2bin(msg["even"])
                signal_bits_odd = pms.hex2bin(msg["odd"])

                type_code_even = int(signal_bits_even[32:37], 2)
                type_code_odd = int(signal_bits_odd[32:37], 2)

                if type_code_even == 11 and type_code_odd == 11:
                    position = self.calcPosition(msg)
                    if position not in self.position:
                        self.position.append(position)

    def calcPosition(self, data):
       
        signal_bits_even = pms.hex2bin(data["even"])
        signal_bits_odd = pms.hex2bin(data["odd"])
        
        message_even = signal_bits_even[32:]
        message_odd = signal_bits_odd[32:]

        if message_odd[21] == '1' and message_even[20] == '0':

            altitude = pms.adsb.altitude(data["even"])

            latitude, longitude = pms.adsb.airborne_position(data["even"], data["odd"], 0, 0)

            return (latitude, longitude, altitude, str(datetime.now()))

    def getPositionStream(self):

        pos_stream = self.position

        self.position = []

        return pos_stream
            
        
