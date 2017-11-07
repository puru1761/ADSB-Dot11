# ADSB Tranceiver over 802.11

This is a tool to broadcast ADS-B over WiFi. It makes use of a wireless interface switched on in monitor mode to send and receive broadcasts. This tool makes use of the scapy Library in python. 

## Usage

Make the python file executable and run it as follows:

```
$ chmod +x ADSB.py
$ ./ADSB.py -m MODE -i INTERFACE
```
First switch your interface into monitor mode as follows:
```
$ airmon-ng start wlan0
```
Send: Usage example:

```
$ ./ADSB.py -m send -i wlan0mon
[I] INFO: Transmitting Beacon through interface 'wlan0mon'
[+] SUCCESS: Broadcast Started!

```

Recv: Usage example:
```
$ ./ADSB.py -m recv -i wlan1mon
[+] SUCCESS: ADS-B Packet received!
[I] INFO: DF -> 17
[I] INFO: CA -> 5
[I] INFO: ICAO -> 0xABCDEF
[I] INFO: DATA ->XXXXXX
[I] INFO: TYPE CODE -> 1
[I] INFO: PARITY -> 567890

```

To view the help:
```
$ ./ADSB.py -h
usage: ADSB.py [-h] -m MODE -i INTERFACE [--ssid SSID]

[X] ADS-B Tranceiver over WiFi [X]

optional arguments:
  -h, --help            show this help message and exit
  -m MODE, --mode MODE  Mode: This can be "recv" or "send" (Default is recv)
  -i INTERFACE, --interface INTERFACE
                        Name of the interface to be used

[*] Author: 0xBADB01

```

## Author

* Puru
* pkulkar6@jhu.edu
