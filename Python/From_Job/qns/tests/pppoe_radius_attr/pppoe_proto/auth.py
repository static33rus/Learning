#!/usr/bin/python3

from .packet import *
from .configure import *

import logging
import pexpect

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

#
# Authentication tests
#


def run_auth_00(test, interface):
    """
    Authentication using PAP
    :param test: Test name
    :param interface:Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: establish pppoed -> send lcp Configuration Request -> recv Configuration-Ack"
        " -> recv Configuration-Request [chap] -> Check Options Configuration-Request [chap]"
        " -> send Configuration-Reject -> recv Configuration-Request [pap] -> send Configuration-Ack"
        " -> send Authenticate-Request PAP -> recv Authenticate-Ack -> no reply".format(test, interface)
    )
    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Configure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if configure_ack is None:
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # check auth in LCP Options
    option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
    if option is None:
        print("    >>> LCP Options do not have Authentication Protocol")
        return False

    auth_proto = check_auth_proto(option, 0xc023)  # 0xc023 - PAP
    if not auth_proto:
        print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc023))
        print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))

    # send configuration-reject
    configuration_reject = create_packet_lcp_config_pkt(configure_req, 0x04)
    print(" -> LCP Configure-Reject")
    packets = send_and_recv(interface, configuration_reject)

    # get configure-request
    print(" <- {0} packet(s)".format(len(packets)))
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # send configure-ack
    config_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    sendp(config_ack, iface=interface)

    # send authenticate request
    ## \x61\x64\x6d\x69\x6e: admin
    auth_request = create_packet_pap(dst, sessionid, '\x61\x64\x6d\x69\x6e', '\x61\x64\x6d\x69\x6e')
    print(" -> PAP Authenticate-Request")
    packets = send_and_recv(interface, auth_request, wait=0.2)

    # get authenticate ack
    print(" <- {0} packet(s)".format(len(packets)))
    auth_ack = find_packet_ppp_lcp(packets, 0x02)
    if auth_ack is None:
        return False

    # no reply
    packets.remove(auth_ack)
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True


def run_auth_01(test, interface):
    """
    Authentication using PAP with wrong username
    :param test: Test name
    :param interface:Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: establish pppoed -> send lcp Configuration Request -> recv Configuration-Ack"
        " -> recv Configuration-Request -> Check Options Configuration-Request[chap] -> send Configuration-Reject"
        " -> recv Configuration-Request [pap]-> send Configuration-Ack"
        " -> send Authenticate-Request PAP [wrong username] -> recv Authenticate-Nak"
        " -> no reply".format(test, interface)
    )

    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Configure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if configure_ack is None:
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # check auth in LCP Options
    option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
    if option is None:
        print("    >>> LCP Options do not have Authentication Protocol")
        return False

    auth_proto = check_auth_proto(option, 0xc023)  # 0xc023 - PAP
    if not auth_proto:
        print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc023))
        print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))

        # send configuration-reject
        configuration_reject = create_packet_lcp_config_pkt(configure_req, 0x04)
        print(" -> LCP Configure-Reject")
        packets = send_and_recv(interface, configuration_reject)

        # get configure-request
        print(" <- {0} packet(s)".format(len(packets)))
        configure_req = find_packet_ppp_lcp(packets, 0x01)
        if configure_req is None:
            return False

        # check auth in LCP Options
        option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
        if option is None:
            print("    >>> LCP Options do not have Authentication Protocol")
            return False

        auth_proto = check_auth_proto(option, 0xc023)  # 0xc023 - PAP
        if not auth_proto:
            print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc023))
            print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))
            return False

    # send configure-ack
    config_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    sendp(config_ack, iface=interface)

    # send authenticate request
    ## \x6f\x64\x6d\x69\x6e\x31: odmin
    ## \x61\x64\x6d\x69\x6e\x31: admin
    auth_request = create_packet_pap(dst, sessionid, '\x6f\x64\x6d\x69\x6e', '\x61\x64\x6d\x69\x6e')
    print(" -> PAP Authenticate-Request")
    packets = send_and_recv(interface, auth_request, wait=1.5)

    # get authenticate ack
    print(" <- {0} packet(s)".format(len(packets)))
    auth_ack = find_packet_ppp_lcp(packets, 0x03)
    if auth_ack is None:
        return False

    # no reply
    packets.remove(auth_ack)
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True

def run_auth_02(test, interface):
    """
    Authentication using PAP with wrong password
    :param test: Test name
    :param interface:Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: establish pppoed -> send lcp Configuration Request -> recv Configuration-Ack"
        " -> recv Configuration-Request -> Check Options Configuration-Request[chap] -> send Configuration-Reject"
        " -> recv Configuration-Request [pap]-> send Configuration-Ack"
        " -> send Authenticate-Request PAP [wrong password] -> recv Authenticate-Nak"
        " -> no reply".format(test, interface)
    )

    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Configure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if configure_ack is None:
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # check auth in LCP Options
    option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
    if option is None:
        print("    >>> LCP Options do not have Authentication Protocol")
        return False

    auth_proto = check_auth_proto(option, 0xc023)  # 0xc023 - PAP
    if not auth_proto:
        print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc023))
        print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))

        # send configuration-reject
        configuration_reject = create_packet_lcp_config_pkt(configure_req, 0x04)
        print(" -> LCP Configure-Reject")
        packets = send_and_recv(interface, configuration_reject)

        # get configure-request
        print(" <- {0} packet(s)".format(len(packets)))
        configure_req = find_packet_ppp_lcp(packets, 0x01)
        if configure_req is None:
            return False

        # check auth in LCP Options
        option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
        if option is None:
            print("    >>> LCP Options do not have Authentication Protocol")
            return False

        auth_proto = check_auth_proto(option, 0xc023)  # 0xc023 - PAP
        if not auth_proto:
            print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc023))
            print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))
            return False

    # send configure-ack
    config_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    sendp(config_ack, iface=interface)

    # send authenticate request
    ## \x6f\x64\x6d\x69\x6e\x31: odmin
    ## \x61\x64\x6d\x69\x6e\x31: admin
    auth_request = create_packet_pap(dst, sessionid, '\x61\x64\x6d\x69\x6e', '\x6f\x64\x6d\x69\x6e')
    print(" -> PAP Authenticate-Request")
    packets = send_and_recv(interface, auth_request, wait=1.5)

    # get authenticate ack
    print(" <- {0} packet(s)".format(len(packets)))
    auth_ack = find_packet_ppp_lcp(packets, 0x03)
    if auth_ack is None:
        return False

    # no reply
    packets.remove(auth_ack)
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True


def run_auth_03(test, interface):
    """
    Authentication using CHAP
    :param test: Test name
    :param interface:Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: establish pppoed -> send lcp Configuration Request -> recv Configuration-Ack"
        " -> recv Configuration-Request [chap] -> Check Options Configuration-Request [chap]"
        " -> send Configuration-Ack -> recv CHAP chellenge -> create CHAP answer -> send CHAP answer"
        " -> recv CHAP success -> no reply".format(test, interface)
    )

    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if configure_ack is None:
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # check auth in LCP Options
    option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
    if option is None:
        print("    >>> LCP Options do not have Authentication Protocol")
        return False

    # check waiting auth proto & auth proto in LCP Option
    auth_proto = check_auth_proto(option, 0xc223)  # 0xc223 - CHAP
    if not auth_proto:
        print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc223))
        print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))
        return False

    # send configure-ack
    config_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, config_ack)

    # get CHAP Chellenge
    print(" <- {0} packet(s)".format(len(packets)))
    chap_challenge = find_packet_ppp_lcp(packets, 0x01)
    if chap_challenge is None:
        return False

    # create CHAP answer
    chap_answer = create_packet_chap_answer(dst, sessionid, chap_challenge, b'admin')
    print(" -> CHAP Answer")
    packets = send_and_recv(interface, chap_answer, wait=1.5)

    # get CHAP success or reject
    print(" <- {0} packet(s)".format(len(packets)))
    chap_success = find_packet_ppp_lcp(packets, 0x03)
    if chap_success is None:
        return False

    # no reply
    packets.remove(chap_success)
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True

def run_auth_04(test, interface):
    """
    Authentication using CHAP
    :param test: Test name
    :param interface:Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: establish pppoed -> send lcp Configuration Request -> recv Configuration-Ack"
        " -> recv Configuration-Request [chap] -> Check Options Configuration-Request [chap]"
        " -> send Configuration-Ack -> recv CHAP chellenge -> create CHAP answer [wrong password] -> send CHAP answer"
        " -> recv CHAP reject -> no reply".format(test, interface)
    )

    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if configure_ack is None:
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # check auth in LCP Options
    option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
    if option is None:
        print("    >>> LCP Options do not have Authentication Protocol")
        return False

    # check waiting auth proto & auth proto in LCP Option
    auth_proto = check_auth_proto(option, 0xc223)  # 0xc223 - CHAP
    if not auth_proto:
        print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc223))
        print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))
        return False

    # send configure-ack
    config_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, config_ack)

    # get CHAP Chellenge
    print(" <- {0} packet(s)".format(len(packets)))
    chap_challenge = find_packet_ppp_lcp(packets, 0x01)
    if chap_challenge is None:
        return False

    # create CHAP answer
    chap_answer = create_packet_chap_answer(dst, sessionid, chap_challenge, b'odmin')
    print(" -> CHAP Answer [wrong password]")
    packets = send_and_recv(interface, chap_answer, wait=1.5)

    # get CHAP reject
    print(" <- {0} packet(s)".format(len(packets)))
    chap_reject = find_packet_ppp_lcp(packets, 0x04)
    if chap_reject is None:
        return False

    # no reply
    packets.remove(chap_reject)
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True


def run_auth_05(test, interface):
    """
    Check change value Idle-timeout and Session timeout recv from radius
    :param test: Test name
    :param interface:Client interface
    :return: True or False
    """

    print(
        "{0} [{1}]: check idle-timeout(30) -> establish session -> check idle-timeout(2)".format(test, interface)
    )

    # check default attribute idle-session on router(30)
    qns_call('\nqns say "enable" --expect "ecorouter#"')
    qns_call('\nqns say "show running-config | include idle-timeout" --expect "idle-timeout 30"')
    qns_call('\nqns say "clear subscribers bmi.0 all" --expect "ecorouter#"')

    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Configure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if configure_ack is None:
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # check auth in LCP Options
    option = find_lcp_option(configure_req[PPP_LCP], 3)  # 3 - Authentication Protocol
    if option is None:
        print("    >>> LCP Options do not have Authentication Protocol")
        return False

    auth_proto = check_auth_proto(option, 0xc023)  # 0xc023 - PAP
    if not auth_proto:
        print("    >>> Wrong Authentication Protocol, searching proto: {proto}".format(proto=0xc023))
        print("    >>> Authentication Protocol in Configuration Request: {opt}".format(opt=option.data))

    # send configuration-reject
    configuration_reject = create_packet_lcp_config_pkt(configure_req, 0x04)
    print(" -> LCP Configure-Reject")
    packets = send_and_recv(interface, configuration_reject)

    # get configure-request
    print(" <- {0} packet(s)".format(len(packets)))
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # send configure-ack
    config_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    sendp(config_ack, iface=interface)

    # send authenticate request
    ## \x61\x64\x6d\x69\x6e: admin
    auth_request = create_packet_pap(dst, sessionid, '\x61\x64\x6d\x69\x6e', '\x61\x64\x6d\x69\x6e')
    print(" -> PAP Authenticate-Request")
    packets = send_and_recv(interface, auth_request, wait=0.2)

    # get authenticate ack
    print(" <- {0} packet(s)".format(len(packets)))
    auth_ack = find_packet_ppp_lcp(packets, 0x02)
    if auth_ack is None:
        return False

    # send Configure-Request IPCP ("0.0.0.0" = first ip 0.0.0.0)
    configure_request_ipcp = create_packet_ipcp_config(dst, sessionid, 0x01, 0x01, "0.0.0.0")
    print(" -> IPCP Configure-Request")
    packets = send_and_recv(interface, configure_request_ipcp)

    # get Configure-Nak IPCP
    print(" <- {0} packet(s)".format(len(packets)))
    configure_nak_ipcp = find_packet_ppp_ipcp(packets, 0x03)
    if configure_nak_ipcp is None:
        return False

    # get ipcp option from Configure-Nak IPCP
    option = find_lcp_option(configure_nak_ipcp[PPP_IPCP], 3)
    if option is None:
        print("    >>> IPCP Options do not have ip address field")
        return False

    ip_addr = option.data  # IP address from option Configure-Nak IPCP packet

    # send Configure-Request IPCP
    configure_ack_ipcp = create_packet_ipcp_config_pkt(configure_nak_ipcp, 0x01, sessionid)
    print(" -> IPCP Configure-Request")
    packets = send_and_recv(interface, configure_ack_ipcp)

    # get configure-request IPCP
    print(" <- {0} packet(s)".format(len(packets)))
    configure_req_ipcp = find_packet_ppp_ipcp(packets, 0x01)
    if configure_req_ipcp is None:
        return False

    # send configure-ack IPCP
    configure_ack_ipcp = create_packet_ipcp_config_pkt(configure_req_ipcp, 0x02, sessionid)
    print(" -> IPCP Configure-Ack")
    packets = send_and_recv(interface, configure_ack_ipcp)

    # # no reply
    # print(" <- {0} packet(s)".format(len(packets)))
    # if (len(packets) > 0):
    #     return False

    # get next echo request
    echo_req = sniff_int(interface, 0x09)
    if echo_req is None:
        return False

    # check recv radius attribute idle-session on router(2)
    qns_call('\nqns say "enable" --expect "ecorouter#"')
    time.sleep(1)
    qns_call('\nqns say "show subscribers bmi.0 192.168.10.2 | include idle timeout" --expect "idle timeout: 2 min"')

    return True


from collections import OrderedDict


def register(testdict):
    testdict.update({'auth_00': run_auth_00})
    testdict.update({'auth_01': run_auth_01})
    testdict.update({'auth_02': run_auth_02})
    testdict.update({'auth_03': run_auth_03})
    testdict.update({'auth_04': run_auth_04})
    testdict.update({'auth_05': run_auth_05})
