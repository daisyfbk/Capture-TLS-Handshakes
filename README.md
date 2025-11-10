# Capturing TLS Handshakes

This program captures TLS handshake data from a specified network interface and saves it into PCAP files. It was specifically designed to monitor handshakes on interfaces that do not support (or have) TCP Segmentation Offload (TSO).
In such environments, handshake data appear as segmented packets to user-space tools such as tcpdump and tshark. However, these tools have limitations: tcpdump lacks stateful monitoring capabilities, while tshark fails to capture segmented packets that contain only data without TLS headers.

## Installation

If you are testing on an interface with TSO, GSO, or GRO enabled, make sure to disable them first.
```
sudo ethtool -K <INTERFACE> tso off gso off gro off
```

Install `libcap-dev` (Debian-based):

```
sudo apt-get install libpcap-dev
```

Download the latest binary release from this project and provide it with execution permissions.

## Quick Start

To monitor the interface this program requires certain priveliges. If not running as root, you need to set the following capacilites: `sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin`

The program runs indefinetily until CTRL-C is passed to it. 

```
./capture-tls-handshakes -i <INTERFACE> -o <OUTPUT_FOLDER> -p <PORT_TO_MONITOR> -c <CAPTURING_TIME>
```

It receives the following input:

> `<INTERFACE>`: Desired interface to capture packets.  
> `<OUTPUT_FOLDER>`: Output folder for the pcaps, which the program creates if it does not exist.    
> `<PORT_TO_MONITOR>`: Restrict the monitored traffic to only a specific port (Default is 443).     
> `<CAPTURING_TIME>`: Rotating interval to record files in a new pcap (Default is 60s).