#!/usr/bin/python3

import sys
import time
import logging
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoED, PPP, PPP_LCP, PPP_LCP_Option, PPPoE, PPPoE_Tag
from scapy.sendrecv import srp
from functools import partial
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from optparse import OptionParser
from optparse import OptionParser
from subprocess import call, DEVNULL
from collections import OrderedDict

#
# Options
#
mac_count = 10
interface_name = 'veth0'
# interface_name = 'enp1s0f1'

file_with_pcap = 'packets_for_test.pcap'


dst_mac = b'\xff\xff\xff\xff\xff\xff'
PPPoE_tags_header = b'\x01\x01\x00\x00\x01\x03\x00\x04'
end = "\x00"


#
# Help defs
#


def remove_pcap_file():
    try:
        os.remove(file_with_pcap)
    except FileNotFoundError:
        pass

def get_next_mac(i):
    """
    create mac addr
    :param i: counter
    :return: mac address
    """
    mac = b'\x78\x8a' + i.to_bytes(4, byteorder='big')
    return mac


def random_hU():
    d = partial(random.randint, 0, 15)
    return b'%0x%0x%0x%0x' % (d(), d(), d(), d())


def random_magic_number():
    m = random.randint(1000, 9999)
    return m


def send_and_recv(interface, packet, wait=1):
    """
    Send packet and return array of received packets array (wait 0.5 sec for answers!)
    :param interface: Client interface
    :param packet: Packet to send
    :param wait: how many sec wait answer packets (default 0.5 sec)
    :return: packets
    """
    packets = []

    response, unanswered = srp(packet, iface=interface, multi=True, timeout=wait, verbose=0)
    for s, r in response:
        if(r[Ether].type == 0x8863 or r[Ether].type == 0x8864):
            packets.append(r)

    return packets


def find_packet_pppoed(packets, code):
    """
    Find PPPoED packets by code in received packets
    :param packets: Received packets
    :param code: Packet code
    :return: None
    """
    pkts = []
    for packet in packets:
        if packet[Ether].type == 0x8863:
            if packet[PPPoED].code == code:
                pkts.append(packet)

        else:
            continue

    return pkts


def find_packet_lcp(packets, code):
    """
    Find LCP packets by code in received packets
    :param packets: Received packets
    :param code: Packet code
    :return: pkts
    """
    pkts = []
    for packet in packets:
        if packet[Ether].type == 0x8864 and packet[PPP].proto == 0xc021:

            if packet[PPP_LCP].code == code:
                pkts.append(packet)

        else:
            continue

    return pkts


def find_packet_ipcp(packets, code):
    """
    Find IPCP packets by code in received packets
    :param packets: Received packets
    :param code: Packet code
    :return: None
    """
    pkts = []
    for packet in packets:
        if packet[Ether].type == 0x8864 and packet[PPP].proto == 0x8021:

            if packet[PPP_IPCP].options != None:
                for option in packet[PPP_IPCP].options:
                    if option.type != 0:
                        print("        {0} : {1}".format(option.type, option.data))

            if packet[PPP_IPCP].code == code:
                pkts.append(packet)

        else:
            continue

    return pkts


def find_ipcp_option(packets, type):
    """
    Take ipcp options
    Search option type 3 (ip addr)
    return option.data
    :param packets: IPCP_option
    :param type: type IPCP_option
    :return: option.data
    """
    ip_list = []

    for packet in packets:
        if packet[Ether].type == 0x8864 and packet[PPP].proto == 0x8021:
            if packet[PPP_IPCP].options != None:

                for option in packet[PPP_IPCP].options:
                    if option.type == type:
                        ip_list.append(option.data)

    return ip_list


#
# Create packets
#


def create_packet_padi(service, number_ses):
    """
    Create PADI packet
    :param service: Service-Name tag
    :return: packet
    """

    tags=[]

    tags.append(PPPoE_Tag(type='Host-Uniq', data=random_hU()))

    if service != None:
        tags.append(PPPoE_Tag(type='Service-Name', data=service))

    packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_next_mac(number_ses), type=0x8863) / \
        PPPoED(version=1, type=1, code=0x09, sessionid=0x0000, tags=tags)

    return packet


def create_packet_padr(dst, src, accookie, acname, service):
    """
    Create PADR packet
    :param dst: Destination MAC
    :param src: Source MAC
    :param accookie: AC-Cookie tag
    :param acname: AC-Name tag
    :param service: Service-Name tag
    :return: packet
    """
    tags=[]

    tags.append(PPPoE_Tag(type='Host-Uniq', data=b'\x08\xf4\x18\x35\x80\xff\xff\xff'))

    if accookie != None:
        tags.append(PPPoE_Tag(type='AC-Cookie', data=accookie))

    if acname != None:
        tags.append(PPPoE_Tag(type='AC-Name', data=acname))

    if service != None:
        tags.append(PPPoE_Tag(type='Service-Name', data=service))

    packet = Ether(dst=dst, src=src, type=0x8863) / \
        PPPoED(version=1, type=1, code=0x19, sessionid=0x0000, tags=tags)
    return packet


def create_packet_lcp_config(dst, src, sessionid, code, magic, id=0x01, mru=1492):
    """
    Create lcp packet
    :param dst: Destination MAC
    :param src: Source MAC
    :param sessionid: PPPoE session id
    :param code: LCP code
    :param id: Message id
    :param mru: MRU value
    :param magic: Magic value
    :return: packet
    """

    options = []

    options.append(PPP_LCP_Option(type=0x01, data=mru.to_bytes(2, byteorder='big')))
    options.append(PPP_LCP_Option(type=0x05, data=magic.to_bytes(4, byteorder='big')))

    packet = Ether(dst=dst, src=src, type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0xc021) / \
        PPP_LCP(code=code, id=id, options=options)

    return packet


def create_packet_lcp_config_pkt(dst, src, sessionid, source, code):
    """
    Take source packet
    Get last fields
    Form new packet
    Then copy last fields
    :param dst: Destination MAC
    :param src: Source MAC
    :param sessionid: PPPoE session id
    :param source: source packet
    :param code: LCP code
    :return: packet
    """

    packet = Ether(dst=dst, src=src, type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0xc021) / \
        source[PPP_LCP]
    packet[PPP_LCP].code = code
    return packet


def create_packet_ipcp_config(dst, src, sessionid, code, id=0x01, ip=b'\x00\x00\x00\x00'):
    """
    Create IPCP Configuration Request packet
    :param dst: Destination MAC
    :param src: Source MAC
    :param sessionid: PPPoE session id
    :param code: LCP code
    :param id: Message id
    :param ip: 0.0.0.0 ip address
    :return: packet
    """

    options = []

    options.append(PPP_IPCP_Option(type=0x03, data=ip))

    packet = Ether(dst=dst, src=src, type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0x8021) / \
        PPP_IPCP(code=code, id=id, options=options)

    return packet


#
# PPPoED tests
#
def perf_test_pppoed_00(test, interface):
    """
    Fast send [mac_count] PADI get PADO
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    remove_pcap_file()

    print("{0} [{1}]: send PADI [no service] * (mac_count) -> get PADO * (mac_count)".format(test, interface))

    # create [mac_count] padi
    for number_ses in range(0, mac_count):
        padi = create_packet_padi('', number_ses)
        wrpcap(file_with_pcap, padi, append=True, sync=True)

    # read file with [mac_count] padi
    pcap_for_send = rdpcap(file_with_pcap)

    # send [mac_count] padi
    print(" -> {0} PADI".format(mac_count))
    packets = send_and_recv(interface, pcap_for_send)

    # get [mac_count] pado
    print(" <- {0} packet(s)".format(len(packets)))
    pkts = find_packet_pppoed(packets, 0x07)
    if pkts is None:
        os.remove(file_with_pcap)
        packets.clear()
        return False

    os.remove(file_with_pcap)
    packets.clear()
    return True


def perf_test_pppoed_01(test, interface):
    """
    Get [mac_count] PADO send PADR get PADS
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    remove_pcap_file()

    print("{0} [{1}]: send PADI [no service] * (mac_count) -> get PADO * (mac_count) -> send PADR * (mac_count)"
          "<- get PADS * (mac_count)".format(test, interface))

    # create [mac_count] padi
    for number_ses in range(0, mac_count):
        padi = create_packet_padi('', number_ses)
        wrpcap(file_with_pcap, padi, append=True, sync=True)

    # read file with [mac_count] padi
    pcap_for_send = rdpcap(file_with_pcap)

    # send [mac_count] padi
    print(" -> {0} PADI".format(mac_count))
    packets = send_and_recv(interface, pcap_for_send)

    # get count packets
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) < mac_count:
        return False

    # get [mac_count] pado
    pkts = find_packet_pppoed(packets, 0x07)
    if pkts is None:
        os.remove(file_with_pcap)
        packets.clear()
        return False

    remove_pcap_file()
    for pado in pkts:
        # get AC-Cookie
        accookie = None
        for tag in pado[PPPoED].tags:
            if tag.type == 260:
                accookie = tag.data
                continue
        if accookie == None:
            print(" AC-Cookie is not set")
            return False

        dst = pado[Ether].src
        src = pado[Ether].dst

        # create PADR answer
        padr = create_packet_padr(dst, src, accookie, None, '')
        wrpcap(file_with_pcap, padr, append=True, sync=True)

    # read file with [mac_count] padr
    pcap_for_send = rdpcap(file_with_pcap)

    # send [mac_count] padr
    print(" -> {0} PADR".format(mac_count))
    packets = send_and_recv(interface, pcap_for_send)

    # get count packets
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) < mac_count:
        return False

    # get [mac_count] pads
    pkts = find_packet_pppoed(packets, 0x65)
    if pkts is None:
        os.remove(file_with_pcap)
        packets.clear()
        return False

    os.remove(file_with_pcap)
    packets.clear()
    return True


def perf_test_pppoed_02(test, interface):
    """
    Get [mac_count] sessions (test ip pool)
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: establish PPPoED -> LCP -> IPCP connections. Check ip address from IPCP Configure Nak."
          "Test router ip pool".format(test, interface))

    remove_pcap_file()

    # create [mac_count] padi
    for number_ses in range(0, mac_count):
        padi = create_packet_padi('', number_ses)
        wrpcap(file_with_pcap, padi, append=True, sync=True)

    # read file with [mac_count] padi
    pcap_for_send = rdpcap(file_with_pcap)

    # send [mac_count] padi
    print(" -> {0} PADI".format(mac_count))
    packets = send_and_recv(interface, pcap_for_send)

    # get count packets
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) < mac_count:
        return False

    # get [mac_count] pado
    pkts = find_packet_pppoed(packets, 0x07)
    if pkts is None:
        os.remove(file_with_pcap)
        packets.clear()
        return False

    remove_pcap_file()
    for pado in pkts:
        # get AC-Cookie
        accookie = None
        for tag in pado[PPPoED].tags:
            if tag.type == 260:
                accookie = tag.data
                continue
        if accookie == None:
            print(" AC-Cookie is not set")
            return False

        dst = pado[Ether].src
        src = pado[Ether].dst

        # create PADR answer
        padr = create_packet_padr(dst, src, accookie, None, '')
        wrpcap(file_with_pcap, padr, append=True, sync=True)

    # read file with [mac_count] padr
    pcap_for_send = rdpcap(file_with_pcap)

    # send [mac_count] padr
    print(" -> {0} PADR".format(mac_count))
    packets = send_and_recv(interface, pcap_for_send)

    # get count packets
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) < mac_count:
        return False

    # get [mac_count] pads
    pkts = find_packet_pppoed(packets, 0x65)
    if pkts is None:
        remove_pcap_file()
        packets.clear()
        return False

    remove_pcap_file()
    for pads in pkts:

        dst = pads[Ether].src
        src = pads[Ether].dst
        sessionid = pads[PPPoED].sessionid

        # create LCP Configuration Request
        lcp_conf_req = create_packet_lcp_config(dst, src, sessionid, 0x01, random_magic_number())
        wrpcap(file_with_pcap, lcp_conf_req, append=True, sync=True)

    # read file with [mac_count] LCP Configutarion Request
    pcap_for_send = rdpcap(file_with_pcap)
    packets.clear()

    # send [mac_count] LCP Configutarion Request
    print(" -> {0} LCP Configutarion Request".format(mac_count))
    packets = send_and_recv(interface, pcap_for_send)

    # get count packets (LCP Configuration Ack && LCP Configuration Request from router)
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) < mac_count:
        return False

    # get LCP Configuration Request
    pkts = find_packet_lcp(packets, 0x01)
    if pkts is None:
        remove_pcap_file()
        packets.clear()
        return False

    remove_pcap_file()
    for lcp_conf_req_srv in pkts:

        dst = lcp_conf_req_srv[Ether].src
        src = lcp_conf_req_srv[Ether].dst
        sessionid = lcp_conf_req_srv[PPPoE].sessionid

        # create LCP Configuration Ack && IPCP Configuration Request
        lcp_conf_ack = create_packet_lcp_config_pkt(dst, src, sessionid, lcp_conf_req_srv, 0x02)
        ipcp_conf_req = create_packet_ipcp_config(dst, src, sessionid, 0x01)
        wrpcap(file_with_pcap, lcp_conf_ack, append=True, sync=True)
        wrpcap(file_with_pcap, ipcp_conf_req, append=True, sync=True)

    # read file with [mac_count] LCP Configutarion Ack
    pcap_for_send = rdpcap(file_with_pcap)
    packets.clear()

    # send [mac_count] LCP Configutarion Ack
    print(" -> {0} LCP Configutarion Ack".format(mac_count))
    print(" -> {0} IPCP Configuration Request".format(mac_count))
    packets = send_and_recv(interface, pcap_for_send, wait=2)
    remove_pcap_file()

    # get count packets
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) < mac_count:
        return False

    # get IPCP Configuration Nak (pool 192.168.10.2-192.168.10.8 = 7 ip address)
    pkts_good = find_packet_ipcp(packets, 0x03)
    print(" <- {0} packet(s) IPCP Configuration Nak".format(len(pkts_good)))
    if len(pkts_good) < 6:
        remove_pcap_file()
        packets.clear()
        return False

    # get ip address from IPCP Configuration Nak packets
    ip_list = find_ipcp_option(pkts_good, 0x03)
    print(ip_list)

    # compare ip address from ip_list(list ip address from conf nak) and ip_pool(ip pool in config file)
    ip_pool = ['192.168.10.2', '192.168.10.3', '192.168.10.4', '192.168.10.5',
               '192.168.10.6', '192.168.10.7',  '192.168.10.8']
    ip_check = list(set(ip_pool) - set(ip_list))
    print(" <- {0} = ip from Nak - ip pool".format(len(ip_check)))
    if len(ip_check) > 0:
        remove_pcap_file()
        packets.clear()
        return False

    # get Termination Request (pool 192.168.10.2-192.168.10.8 = 7 ip address, other clients(3) get Termination Request)
    pkts_bad = find_packet_lcp(packets, 0x05)
    print(" <- {0} packet(s) Termination Request".format(len(pkts_bad)))
    if len(pkts_bad) < 2:
        remove_pcap_file()
        packets.clear()
        return False

    remove_pcap_file()
    packets.clear()

    return True
#
# Parser options
#

parser = OptionParser()
parser.add_option("-t", "--test", dest="test", default="", help="test name")
parser.add_option("-i", "--interface", dest="interface", default=interface_name, help="client interface")

(options, args) = parser.parse_args()


#
# Test dictionary
#

testdict = OrderedDict()
testdict.update({'pppoed_00': perf_test_pppoed_00})
testdict.update({'pppoed_01': perf_test_pppoed_01})
testdict.update({'pppoed_02': perf_test_pppoed_02})

# Run test
#  - test: Test name
#  - interface: Client interface
def run(test, interface):
    """
    Run test
    :param test: Test name
    :param interface: Client interface
    :return:
    """

    print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

    success = testdict[test](test, interface)
    if success:
        print(" >>> SUCCESS")
    else:
        print(" >>> FAIL")

    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")

    if not success:
        sys.exit(1)


# Main function
if options.test == '':
    for key in testdict:
        run(key, options.interface)
else:
    if options.test in testdict:
       run(options.test, options.interface)
