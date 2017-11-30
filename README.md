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
#### Library Dependencies:

In order to run the provided script, we must make use of a library called pyModeS. In order to install pyModeS, run the following commands:

```
$ pip install pyModeS
```

#### Usage example:

Depending on the interface and the mode used to run the calling script, we can call a variety of functions from the ```ADSB_lib``` API. These functions along with the imports are listed below as follows:

First, import the required classes from ```ADSB.ADSB_lib```
```
from ADSB.ADSB_lib import ADSB_SDR_Thread, ADSB_MSG
```

After this, the ```ADSB_MSG``` class contains a create message which can be used to create valid ADS-B even and odd position messages as follows:

```python
adsb_even_msg, adsb_odd_msg = ADSB_MSG().create(icao, latitude, longitude, altitude)

```

The next step is to create a sender thread in order to send these messages. This can be done by:

```python
sdr = ADSB_SDR_Thread('send', interface)
sdr.updateMsg(adsb_even_msg, adsb_odd_msg)
sdr.start()
```
The above code will result in the specified interface broadcasting valid ADS-B position messages over 802.11 (WiFi). These messages can then be received by another interface configured in monitor mode to sniff WiFi traffic using this API as follows:

```python
sdr_recv = ADSB_SDR_Thread('recv', interface)
sdr_recv.start()
```

Here the receiving thread will start and will print out the current location of the aircraft to stdout by decoding the received messages and calculating the aircraft location (latitude, longitude, altitude).

The provided script ```ADSB.py``` is a testing script to check if the library works. It can be run to send and receive test ADS-B messages.

To view the help for this script:
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
