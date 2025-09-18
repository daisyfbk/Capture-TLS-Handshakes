# Capturing TLS Handshakes

This project captures only TLS handshake packets from an interface and saves them to pcap files. 


## Quick Start

Disable TSO, GSO and GRO in the monitored interface so packets come segmented:

```
sudo ethtool -K <INTERFACE> tso off gso off gro off
```

Install `libcap-dev` (Debian-based):

```
sudo apt-get install libpcap-dev
```

Download the latest binary release from this project and run it.

## Running

To monitor the interface this program requires certain priveliges. If not running as root, you need to set the following capacilites: `sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin`

The program runs indefinetily until CTRL-C is passed to it. It receives the following input:

> `<INTERFACE>`: Desired interface to capture packets.  
> `<OUTPUT_FOLDER>`: Output folder for the pcaps which the program creates if it does not exist.    
> `<PORT_TO_MONITOR>`: Restrict the monitored traffic to only a specific port (Default is 443).
> `<CAPTURING_TIME>`: Rotating interval to record files in a new pcap (Default is 60s).