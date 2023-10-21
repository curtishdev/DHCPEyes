# DHCPEyes :eyes:
**Intercept requests passively of DHCP from own network!**

**Chnages v1.2 - v1.3**
- Changed the code structure, rewritten from Python2 and Scapy 2.44 to the Latest Version of Python3.11+ and the latest Scapy 2.5.0, optimized, no kernel changes.

<img
src="https://raw.githubusercontent.com/vincenzogianfelice/DHCPEyes/master/media/demo.png"
alt="DemoImage"
/>

# Authors
- **Vincenzo Gianfelice**
- **Contact**: _developer.vincenzog@gmail.com_
- **BTC**(donation): *3EwV4zt9r5o4aTHyqjcM6CfqSVirSEmN6y*
- **Forked by CurtishDEV**

**Platforms**
Rewritten for MacOS, 95% working code for Windows, just few changes if needed.


# Prerequisites
Require **python3.11+**

- scapy >= 2.5.0 (Latest one)
- termcolor 
- colorama (If you want or Windows :))

###### Windows
1. Download zip
2. Unzip, run CMD as Administrator
3. Use options from the list to run the code
4. Enjoy!

**All CMDS**
For all options, use 




# Installation
```
pip3 (pip) install -r requirements.txt
```

# Usage
```
    ____  __  ____________  ______
   / __ \/ / / / ____/ __ \/ ____/_  _____  _____
  / / / / /_/ / /   / /_/ / __/ / / / / _ \/ ___/
 / /_/ / __  / /___/ ____/ /___/ /_/ /  __(__  )
/_____/_/ /_/\____/_/   /_____/\__, /\___/____/
                              /____/

        * Passive DHCP Listener! (v1.3) *

Usage: python3 main.py -i <interface>


     -i        Interface for listening
Optional:
     -o <arg>  File Output Save
     -t <arg>  Options types: DHCPD  (discover)
                              DHCPR  (request)
                              DHCPN  (nak)
                              DHCPI  (inform)
               Default print all options
```

#### Examples
```
python3 main.py -i wlan0 -t DHCPR              # Intercept only DHCPREQUEST on wlan0
python3 main.py -t DHCPI -i wlan0 -t DHCPD     # Intercept DHCPINFORM and DHCPDISCOVER
python3 main.py -i wlan0                       # Intercept all
```

###### Windows
```
python3 main.py -i "Connessione alla rete locale (LAN)" -t DHCPR  # Using "Connessione alla rete locale (LAN)" provided from output of command netsh
```
