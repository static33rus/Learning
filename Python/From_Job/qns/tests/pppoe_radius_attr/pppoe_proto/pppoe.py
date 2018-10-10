#!/usr/bin/python3

from .packet import *

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

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
    print("{0} [{1}]: send PADI [no service] -> receive PADO -> send PADR [no service] -> receive PADS".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # get pado
    print(" <- {0} packet(s)".format(len(packets)))
    pado = find_packet_pppoed(packets, 0x07)
    if pado is None:
        return False

    # get AC-Cookie
    accookie = None;
    for tag in pado[PPPoED].tags:
        if tag.type == 260:
            accookie = tag.data
            break
    if accookie == None:
        print(" AC-Cookie is not set")
        return False

    padr = create_packet_padr(pado[Ether].src, accookie, None, '')
    print(" -> PADR")
    packets = send_and_recv(interface, padr)

    # get pads
    print(" <- {0} packet(s)".format(len(packets)))
    pads = find_packet_pppoed(packets, 0x65)
    if pads is None:
        return False

    print(" Session ID: {:04x}".format(pads[PPPoED].sessionid))
    if pads[PPPoED].sessionid == 0:
        return False

    return True


def run_pppoe_01(test, interface):
    """
    Test pppoe_01
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: send PADI [service] -> receive PADO -> send PADR [existing service] -> receive PADS".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('ololo')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # get pado
    print(" <- {0} packet(s)".format(len(packets)))
    pado = find_packet_pppoed(packets, 0x07)
    if(pado is None):
        return False

    # get AC-Cookie
    accookie = None;
    for tag in pado[PPPoED].tags:
        if(tag.type == 260):
            accookie = tag.data
            break
    if(accookie == None):
        print(" AC-Cookie is not set")
        return False

    padr = create_packet_padr(pado[Ether].src, accookie, None, 'ololo')
    print(" -> PADR")
    packets = send_and_recv(interface, padr)

    # get pads
    print(" <- {0} packet(s)".format(len(packets)))
    pads = find_packet_pppoed(packets, 0x65)
    if(pads is None):
        return False

    print(" Session ID: {:04x}".format(pads[PPPoED].sessionid))
    if(pads[PPPoED].sessionid == 0):
        return False

    return True


def run_pppoe_02(test, interface):
    """
    Test pppoe_02
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: send PADI [service] -> receive PADO -> send PADR [not existing service] -> receive PADS error".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('ololo')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # get pado
    print(" <- {0} packet(s)".format(len(packets)))
    pado = find_packet_pppoed(packets, 0x07)
    if pado is None:
        return False

    # get AC-Cookie
    accookie = None
    for tag in pado[PPPoED].tags:
        if tag.type == 260:
            accookie = tag.data
            break
    if accookie == None:
        print(" AC-Cookie is not set")
        return False

    padr = create_packet_padr(pado[Ether].src, accookie, None, 'hz')
    print(" -> PADR")
    packets = send_and_recv(interface, padr)

    # get pads
    print(" <- {0} packet(s)".format(len(packets)))
    pads = find_packet_pppoed(packets, 0x65)
    if pads is None:
        return False

    print(" Session ID: {:04x}".format(pads[PPPoED].sessionid))
    if pads[PPPoED].sessionid != 0:
        return False

    return True


def run_pppoe_03(test, interface):
    """
    Test pppoe_03
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: send PADI [not existing service] -> no reply".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('hz')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True


def run_pppoe_04(test, interface):
    """
    Test pppoe_04
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: send PADI [service] -> receive PADO -> send PADR [bad cookie] -> no reply".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('ololo')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # get pado
    print(" <- {0} packet(s)".format(len(packets)))
    pado = find_packet_pppoed(packets, 0x07)
    if pado is None:
        return False

    # get AC-Cookie
    accookie = None
    for tag in pado[PPPoED].tags:
        if(tag.type == 260):
            accookie = tag.data
            break
    if accookie == None:
        print(" AC-Cookie is not set")
        return False

    # corrupt AC-Cookie
    ba = bytearray(accookie)
    ba[0] = ~ba[0] & 0xFF

    padr = create_packet_padr(pado[Ether].src, bytes(ba), None, 'ololo')
    print(" -> PADR")
    packets = send_and_recv(interface, padr)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True


def run_pppoe_05(test, interface):
    """
    Send PADT after PADO
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print("{0} [{1}]: send PADI [no service] -> receive PADO -> send PADT [ac cookie, 0x0000 session] ->"
          " send PADR [no service] -> receive PADS".format(test, interface))

    # send padi & receive pado
    padi = create_packet_padi('')
    print(" -> PADI")
    packets = send_and_recv(interface, padi)

    # get pado
    print(" <- {0} packet(s)".format(len(packets)))
    pado = find_packet_pppoed(packets, 0x07)
    if pado is None:
        return False

    # get AC-Cookie
    accookie = None
    for tag in pado[PPPoED].tags:
        if tag.type == 260:
            accookie = tag.data
            break
    if accookie == None:
        print(" AC-Cookie is not set")
        return False

    dst = pado[Ether].src

    # send PADT
    padt = create_packet_padt(dst, 0x0000, accookie, None)
    print(" -> PADT")
    packets = send_and_recv(interface, padt)

    # send PADR
    padr = create_packet_padr(pado[Ether].src, accookie, None, '')
    print(" -> PADR")
    packets = send_and_recv(interface, padr)

    # get PADS
    print(" <- {0} packet(s)".format(len(packets)))
    pads = find_packet_pppoed(packets, 0x65)
    if pads is None:
        return False

    return True

from collections import OrderedDict

def register(testdict):
    testdict.update({'pppoe_00': run_pppoe_00})
    testdict.update({'pppoe_01': run_pppoe_01})
    testdict.update({'pppoe_02': run_pppoe_02})
    testdict.update({'pppoe_03': run_pppoe_03})
    testdict.update({'pppoe_04': run_pppoe_04})
    testdict.update({'pppoe_05': run_pppoe_05})
