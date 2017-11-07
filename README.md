# ADSB Tranceiver over 802.11

This is a tool to broadcast ADS-B over WiFi. It makes use of a wireless interface switched on in monitor mode to send and receive broadcasts. This tool makes use of the scapy Library in python. 

## Usage

Make the python file executable and run it as follows:

```
$ chmod +x ADSB.py
$ ./ADSB.py -m MODE -i INTERFACE [--ssid SSID]
```
First switch your interface into monitor mode as follows:
```
$ airmon-ng start wlan0
```
Send: Usage example:

```
$ ./ADSB.py -m send -i wlan0mon --ssid TestAP
[I] INFO: Beacon Frame created with SSID: 'TestAP'
[I] INFO: Transmitting Beacon through interface 'wlan0mon'
[+] SUCCESS: Broadcast Started!

```

Recv: Usage example:
###### TODO: Complete ADS-B parsing
```
$ ./ADSB.py -m recv -i wlan1mon
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
  --ssid SSID           Your ADS-B Broadcast name

[*] Author: 0xBADB01

```

## Author

* Puru
* pkulkar6@jhu.edu
