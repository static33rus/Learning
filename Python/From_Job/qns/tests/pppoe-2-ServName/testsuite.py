#!/usr/bin/python3

import sys
import logging
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoED, PPP, PPP_LCP, PPP_LCP_Option, PPPoE, PPPoE_Tag, PPP_IPCP, PPP_IPCP_Option
from scapy.sendrecv import srp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from optparse import OptionParser
from optparse import OptionParser
from subprocess import call, DEVNULL

from collections import OrderedDict


def send_and_recv(interface, packet):
    """
    Send packet and return array of received packets array (wait 0.5 sec for answers!)
    :param interface: Client interface
    :param packet: Packet to send
    :return: packets
    """
    packets = []

    response, unanswered = srp(packet, iface=interface, multi=True, timeout=0.5, verbose=0)
    for s, r in response:
        if(r[Ether].type == 0x8863 or r[Ether].type == 0x8864):
            packets.append(r)

    return packets


def find_packet_pppoed(packets, code):
    """
    Find PPPoED packet by code in received packets
    :param packets: Received packets
    :param code: Packet code
    :return: None
    """
    i = 0
    for packet in packets:
        if(packet[Ether].type == 0x8863):
            print("    >>> PPPOED PACKET[{0}] code {1}".format(i, packet[PPPoED].code))
            for tag in packet[PPPoED].tags:
                if (tag.type != 0):
                    print("        {0} : {1}".format(tag.type, tag.data))
            if(packet[PPPoED].code == code):
                return packet
        else:
            print("    >>> ETHERNET PACKET[{0}]: {1}".format(i, packet[Ether].type))

        i = i + 1

    return None


def create_packet_padi(service):
    """
    Create PADI packet
    :param service: Service-Name tag
    :return: packet
    """
    tags=[]

    tags.append(PPPoE_Tag(type='Host-Uniq', data=b'\x08\xf4\x18\x35\x80\xff\xff\xff'))

    if service != None:
        tags.append(PPPoE_Tag(type='Service-Name', data=service))

    packet = Ether(dst="ff:ff:ff:ff:ff:ff", src="32:ef:21:95:12:0a", type=0x8863) / \
        PPPoED(version=1, type=1, code=0x09, sessionid=0x0000, tags=tags)
    return packet

#
# PPPoE tests
#


def run_pppoe_00(test, interface):
    """
    Test pppoe_00
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: send PADI [no service] -> receive PADO [service ololo]".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # get pado
    print(" <- {0} packet(s)".format(len(packets)))
    pado = find_packet_pppoed(packets, 0x07)
    if pado is None:
        return False

    # get service-name
    servname = None
    for tag in pado[PPPoED].tags:
        if tag.type == 257:
            servname = tag.data
            break
    if servname == None:
        print(" Service-Name is not set")
        return False
    if servname == 'servName01':
        print(" Wrong Service-name")
        return False

    return True


def run_pppoe_01(test, interface):
    """
    Test pppoe_00
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: send PADI [servName01] -> no reply".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('servName01')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True

#
# Parser options
#

parser = OptionParser()
parser.add_option("-t", "--test", dest="test", default="", help="test name")
parser.add_option("-i", "--interface", dest="interface", default="veth0", help="client interface")

(options, args) = parser.parse_args()

#
# Test management
#

# Test dictionary
testdict = OrderedDict()
testdict.update({'pppoe_00': run_pppoe_00})
testdict.update({'pppoe_01': run_pppoe_01})


# Run test
#  - test: Test name
#  - interface: Client interface
def run(test, interface):
    print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

    success = testdict[test] (test, interface)
    if(success):
        print(" >>> SUCCESS")
    else:
        print(" >>> FAIL")

    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")

    if(not success):
        sys.exit(1)

# Main function
if options.test == '':
    for key in testdict:
        run(key, options.interface)
else:
    if options.test in testdict:
        run(options.test, options.interface)
