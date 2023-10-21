#!/usr/bin/env python3.10
## Coded by vincenzogianfelice <developer.vincenzog@gmail.com> with <3, Modfied by CurtishDEV github.com/curtishDEV with <3, we do our best for you!
#v1.3 = Python3 Version with few changes :)

import base64
import sys
import time
import os
from termcolor import colored
from scapy.all import Ether, DHCP, IP, sniff
if (os.name == 'nt'):
    import colorama
    colorama.init()

# Constant variables
VERSION = 'v1.3'

# DHCP Message Type - RFC2132/Page-4 (https://tools.ietf.org/html/rfc2132#page-4) ##
# For now, not all "types" will be used, as the client, once it has determined the DHCP destination server,
# sends packets directly to the server (not in broadcast), making passive interception ineffective.
# Soon the ability to intercept requests/responses between the client/server (MITM) will be added.
# Stay Tuned! ;)
DHCPDISCOVER = 1    # Used
DHCPOFFER = 2       # No
DHCPREQUEST = 3     # Used
DHCPDECLINE = 4     # No
DHCPACK = 5         # No
DHCPNAK = 6         # Used
DHCPRELEASE = 7     # No
DHCPINFORM = 8      # Used

# DHCPOptions of Scapy
# (https://github.com/secdev/scapy/blob/development/scapy/layers/dhcp.py)
# `at line 112`. Actual version of scapy is 2.4.4, using actual 2.5.0 for correct working.
MESSAGE_DHCP = 'message-type'
ERROR_MESSAGE = 'error_message'
REQUEST_ADDRESS = 'requested_addr'
ADDRESS_SERVER_DHCP = 'server_id'
VENDOR = 'vendor_class_id'
HOSTNAME = 'hostname'

# Global variables for the script
REQUESTED = list()      # Total devices connected to the network (via DHCP)
TOT_DEVICES = list()    # Total captured devices

def logo():
    LOGO = 'ICAgIF9fX18gIF9fICBfX19fX19fX19fX18gIF9fX19fXyAgICAgICAgICAgICAgIAogICAvIF9fIFwvIC8gLyAvIF9fX18vIF9fIFwvIF9fX18vXyAgX19fX18gIF9fX19fCiAgLyAvIC8gLyAvXy8gLyAvICAgLyAvXy8gLyBfXy8gLyAvIC8gLyBfIFwvIF9fXy8KIC8gL18vIC8gX18gIC8gL19fXy8gX19fXy8gL18vIC8gIF9fKF9fICApIAovX19fX18vXy8gL18vXF9fX18vXy8gICAvX19fX18vXF9fLCAvXF9fXy9fX19fLyAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC9fX19fLyAgICAgICAgICAgICAK'

    print(base64.b64decode(LOGO).decode('ascii'))
    print('\t* Passive DHCP Listener! ('+VERSION+') *')
    print('')

def help():
    print('Usage: {} -i <interface>'.format(sys.argv[0]))
    print('')
    print('     -i        Interface for listening')
    print('Optional:')
    print('     -o <arg>  File Output Save')
    print('     -t <arg>  Options types: DHCPD  (discover)')
    print('                              DHCPR  (request)')
    print('                              DHCPN  (nak)')
    print('                              DHCPI  (inform)')
    print('               Default print all options')

    if (os.name == 'nt'):
        print('')
        print('')
        print('(PS). In Windows, type "netsh interface show interface" to show the names of interfaces')

def dhcp_options_search(pkts):
    data = [pkts[DHCP].options[0][1]]
    for ex in pkts[DHCP].options:
        if REQUEST_ADDRESS in ex:
            data.append((REQUEST_ADDRESS, ex[1]))
        elif ADDRESS_SERVER_DHCP in ex:
            data.append((ADDRESS_SERVER_DHCP, ex[1]))
        elif VENDOR in ex:
            data.append((VENDOR, ex[1]))
        elif HOSTNAME in ex:
            data.append((HOSTNAME, ex[1]))
        elif ERROR_MESSAGE in ex:
            data.append((ERROR_MESSAGE, ex[1]))
    return data

def parser_packet(pkts):
    if (not pkts):
        return

    mac_addr = pkts[Ether].src
    ip_src = pkts[IP].src
    ip_dst = pkts[IP].dst
    address = '???'
    vendor = '???'
    address_server_dhcp = '???'
    hostname = '???'
    error_msg = '???'

    data = dhcp_options_search(pkts)
    if (not data):
        return

    TOT_DEVICES.append(mac_addr)
    type_option = data[0]

    del data[0]

    time_capture = tuple(time.localtime())
    # Check based on the value of the '-t' option and/or the type of incoming packet
    if type_option == DHCPDISCOVER and ('DHCPD' in type_dhcp or not type_dhcp):
        option_dhcp = 'DHCPDISCOVER'
        format_syntax = '[%s] %s (%s (%s)) %s: %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), option_dhcp, mac_addr, vendor, colored(\'host\', \'yellow\', attrs=[\'bold\']), hostname)'
    elif type_option == DHCPREQUEST and ('DHCPR' in type_dhcp or not type_dhcp):
        REQUESTED.append(mac_addr)

        option_dhcp = colored('DHCPREQUEST', 'white', attrs=['bold'])
        format_syntax = '[%s] %s (%s) CLIENT -> [%s (%s)] %s: %s %s: %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), option_dhcp, colored(address_server_dhcp, \'blue\', attrs=[\'bold\']), mac_addr, vendor, colored(\'addr\', \'yellow\', attrs=[\'bold\']), address, colored(\'host\', \'yellow\', attrs=[\'bold\']), hostname)'
    elif type_option == DHCPNAK and ('DHCPN' in type_dhcp or not type_dhcp):
        option_dhcp = 'DHCPNAK'
        format_syntax = '[%s] %s (%s from %s) (%s) via %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), colored(option_dhcp, \'red\', attrs=[\'bold\']), mac_addr, colored(ip_src, \'blue\', attrs=[\'bold\']), error_msg, ip_dst)'
    elif type_option == DHCPINFORM and ('DHCPI' in type_dhcp or not type_dhcp):
        option_dhcp = 'DHCPINFORM'
        format_syntax = '[%s] %s [%s (%s)] %s: %s %s: %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), option_dhcp, mac_addr, vendor, colored(\'addr\', \'yellow\', attrs=[\'bold\']), ip_src, colored(\'host\', \'yellow\', attrs=[\'bold\']), hostname)'
    else:
        return

    for ex in data:
        if REQUEST_ADDRESS in ex:
            address = ex[1]
        elif ADDRESS_SERVER_DHCP in ex:
            address_server_dhcp = ex[1]
        elif VENDOR in ex:
            vendor = ex[1].decode('utf8')
        elif HOSTNAME in ex:
            hostname = ex[1].decode('utf8')
        elif ERROR_MESSAGE in ex:
            error_msg = ex[1].decode('utf8')

        if (file_out):
            with open(file_out, 'a+') as fd:
                fd.write('{}: {} server_dhcp={} mac={} vendor={} address={} hostname={} errorr_msg={}'.format(time.strftime("%d-%m-%y-%H-%M", time_capture), option_dhcp, address_server_dhcp, mac_addr, vendor, address, hostname, error_msg))
                fd.write('\n')

    print((format_syntax) % eval(value_syntax))

if __name__ == '__main__':
    interface = None
    type_dhcp = list()
    file_out = None

    logo()

    op = sys.argv[1::2]
    val = sys.argv[2::2]
    if (len(sys.argv) < 2 or len(op) != len(val)):
        help()
        sys.exit(1)

    # Simple parsing of input options
    i = 0
    for o in op:
        if (o == '-o'):
            file_out = val[i]
        elif (o == '-t'):
            if val[i] != 'DHCPD' and val[i] != 'DHCPR' and val[i] != 'DHCPN' and val[i] != 'DHCPI':
                help()
                sys.exit(1)

            type_dhcp.append(val[i])
        elif (o == '-i'):
            interface = val[i]
        i += 1

    # Check root permissions
    if (os.name == 'posix'):
        if (os.getuid() != 0):
            print('Please run as root')
            sys.exit(1)

    start = time.time()
    sniff(iface=interface, prn=parser_packet, store=False, filter=('udp port 67 and port 68'))
    end = time.time()-start

    if (end < 60):
        who_time = '{} seconds'.format(int(end))
    elif (end >= 60 and end < 3600):
        who_time = '{} minutes'.format(int(end/60))
    else:
        who_time = '{} hours'.format(int(end/3600))

    print('')
    print('\r[+] {}: {} devices ({} {})'.format(who_time,
                                            len(set(TOT_DEVICES)),
                                            len(set(REQUESTED)),
                                            colored('connected', 'yellow', attrs=['bold'])))
