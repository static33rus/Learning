#!/usr/bin/python3

from .packet import *

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

#
# PPP tests
#

# Test ppp_00
#  - test: Test name
#  - interface: Client interface
def run_ppp_00(test, interface):
    print("{0} [{1}]: send Config-Request [mru 1492] -> receive Config-Ack [mru 1492] -> receive Config-Request [mru 1492] -> send Config-Ack [mru 1492] -> no reply".format(test, interface))

    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if(pads == None):
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if(configure_ack is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_ack[PPP_LCP].options, 1492)):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if(configure_req is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_req[PPP_LCP].options, 1492)):
        return False

    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack)

    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if(echo_req is None):
        return False

    # no more packets
    packets.remove(echo_req)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True

# Test ppp_01
#  - test: Test name
#  - interface: Client interface
def run_ppp_01(test, interface):
    print("{0} [{1}]: send Configure-Request [mru 512] -> receive Configure-Nak [mru 1492] -> send Configure-Request [mru 1492] -> receive Configure-Ack [mru 1492] -> receive Configure-Request [mru 1492] -> send Configure-Ack [mru 1492] -> no reply".format(test, interface))

    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if(pads == None):
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 512, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-nak
    print(" <- {0} packet(s)".format(len(packets)))
    configure_nak = find_packet_ppp_lcp(packets, 0x03)
    if(configure_nak is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_nak[PPP_LCP].options, 1492)):
        return False

    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if(configure_ack is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_ack[PPP_LCP].options, 1492)):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if(configure_req is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_req[PPP_LCP].options, 1492)):
        return False

    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack)

    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if(echo_req is None):
        return False

    # no more packets
    packets.remove(echo_req)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True

# Test ppp_02
#  - test: Test name
#  - interface: Client interface
def run_ppp_02(test, interface):
    print("{0} [{1}]: send Configure-Request [mru 9000] -> receive Configure-Ack [mru 9000] -> receive Configure-Request [mru 1492] -> send Configure-Ack [mru 1492] -> no reply".format(test, interface))

    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if(pads == None):
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 9000, 1)
    print(" -> LCP Configure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if(configure_ack is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_ack[PPP_LCP].options, 9000)):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if(configure_req is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_req[PPP_LCP].options, 1492)):
        return False

    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack)

    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if(echo_req is None):
        return False

    # no more packets
    packets.remove(echo_req)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True

# Test ppp_03
#  - test: Test name
#  - interface: Client interface
def run_ppp_03(test, interface):
    print("{0} [{1}]: send Configure-Request [mru 1492] -> receive Configure-Ack [mru 1492] -> receive Configure-Request [mru 1492] -> send Configure-Nak [mru 512] -> receive Configure-Request [mru 512] -> send Configure-Ack [mru 512] -> no reply".format(test, interface))

    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if(pads == None):
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if(configure_ack is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_ack[PPP_LCP].options, 1492)):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if(configure_req is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_req[PPP_LCP].options, 1492)):
        return False

    # trololo
    config_nak = create_packet_lcp_config(dst, sessionid, 0x03, configure_req[PPP_LCP].id, 512, 1)
    print(" -> LCP Congigure-Nak")
    packets = send_and_recv(interface, config_nak)

    # get configure-request
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if(configure_req is None):
        return False

    # validate mru
    if (not validate_lcp_options(configure_req[PPP_LCP].options, 512)):
        return False

    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack)

    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if(echo_req is None):
        return False

    # no more packets
    packets.remove(echo_req)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True

# Test ppp_04
#  - test: Test name
#  - interface: Client interface
def run_ppp_04(test, interface):
    print(
        "{0} [{1}]: send Configure-Request -> recv Configure-Ack -> recv Configure-Request ->  send Configure-Ack -> "
        "send Echo-Request -> recv Echo-Reply -> no reply".format(test, interface)
    )

    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if(pads == None):
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 0x01)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if(configure_ack is None):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if (configure_req is None):
        return None

    # send configure-ack
    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack)
    
    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if(echo_req is None):
        return False

    # no more packets
    packets.remove(echo_req)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    # send echo-request
    echo_request = create_packet_echo_request(dst, sessionid, 0x09, 0x01, 1)
    print(" -> Echo Request")
    packets = send_and_recv(interface, echo_request)

    # get echo-reply
    print(" <- {0} packet(s)".format(len(packets)))
    echo_reply = find_packet_ppp_lcp(packets, 0x0a)
    if (echo_reply is None):
        return False

    # no reply
    packets.remove(echo_reply)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
       return False

    return True


# Test ppp_05
#  - test: Test name
#  - interface: Client interface
def run_ppp_05(test, interface):
    print(
        "{0} [{1}]: send Configure-Request -> recv Configure-Ack -> recv Configure-Request -> send Echo-Request ->"
        " no reply".format(test, interface)
    )
    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if (pads == None):
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
    if (configure_ack is None):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if (configure_req is None):
        return False

    # send echo-request
    echo_request = create_packet_echo_request(dst, sessionid, 0x09, 0x01, 1)
    print(" -> Echo Request")
    packets = send_and_recv(interface, echo_request)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True


# Test ppp_06
#  - test: Test name
#  - interface: Client interface
def run_ppp_06(test, interface):
    print(
        "{0} [{1}]: send Termination-Request -> recv Code-Reject -> no reply".format(test, interface)
    )
    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if (pads == None):
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send Termination-Request
    term_request = create_packet_lcp_without_options(dst, sessionid, 0x05, 0x01, 4)
    print(" -> LCP Termination-Request")
    packets = send_and_recv(interface, term_request)

    # get code-reject
    print(" <- {0} packet(s)".format(len(packets)))
    code_reject = find_packet_ppp_lcp(packets, 0x07)
    if (code_reject is None):
        return False

    # no reply
    packets.remove(code_reject)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True


# Test ppp_07
#  - test: Test name
#  - interface: Client interface
def run_ppp_07(test, interface):
    print(
        "{0} [{1}]: send Configuration-Request -> recv Configuration-Ack -> recv Configuration-Request ->"
        " send Termination-Request -> no reply".format(test, interface)
    )
    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if (pads == None):
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
    if (configure_ack is None):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if (configure_req is None):
        return False

    # send termination-request
    term_request = create_packet_lcp_without_options(dst, sessionid, 0x05, 0x01, 4)
    print(" -> LCP Termination-Request")
    packets = send_and_recv(interface, term_request)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True


# Test ppp_08
#  - test: Test name
#  - interface: Client interface
def run_ppp_08(test, interface):
    print(
        "{0} [{1}]: send PADT -> send Configuration-Request -> no reply".format(test, interface)
    )
    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if (pads == None):
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # get AC-Cookie
    accookie = None
    for tag in pads[PPPoED].tags:
        if(tag.type == 260):
            accookie = tag.data
            break
    if(accookie == None):
        print(" AC-Cookie is not set")
        return None

    # send PADT
    padt = create_packet_padt(dst, sessionid, accookie, 'Test abort session')
    print(" -> PADT")
    packets = send_and_recv(interface, padt)

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True


# Test ppp_09
#  - test: Test name
#  - interface: Client interface
def run_ppp_09(test, interface):
    print(
            "{0} [{1}]: send Configuration-Request -> recv Configuration-Ack -> recv Configuration-Request ->"
            "send Configuration-Ack -> send Termination-Request -> recv Termination-Ack -> recv Termination-Request ->"
            " send Termination-Ack -> no reply".format(test, interface)
        )
    # establish pppoe session
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

    # send configure-ack
    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    sendp(configure_ack, iface=interface)

    # send termination-request
    termination_request = create_packet_lcp_without_options(dst, sessionid, 0x05, 0x01, 4)
    print(" -> LCP Termination-Request")
    packets = send_and_recv(interface, termination_request)

    # get termination-ack
    print(" <- {0} packet(s)".format(len(packets)))
    termination_ack = find_packet_ppp_lcp(packets, 0x06)
    if termination_ack is None:
        return False

    # get termination_request
    packets.remove(termination_ack)
    termination_request = find_packet_ppp_lcp(packets, 0x05)
    if termination_request is None:
        return False

    # send termination-ack
    termination_ack = create_packet_lcp_config_pkt(termination_request, 0x06)
    print(" -> LCP Termination-Ack")
    packets = send_and_recv(interface, termination_ack)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True

# Test ppp_10
#  - test: Test name
#  - interface: Client interface
def run_ppp_10(test, interface):
    """
    establish pppoed / LCP / IPCP
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: send Configuration-Request_ipcp -> recv Configuration-nak_ipcp -> send Configuration-Request_ipcp"
        "-> recv Configuration-Ack_ipcp -> recv Configuration-Request_ipcp -> send Configuration-Ack_ipcp ->"
            " no reply".format(test, interface)
    )
    # establish pppoe session
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

    # send configure-ack
    config_ack = create_packet_lcp_config(dst, sessionid, 0x02, configure_req[PPP_LCP].id, 512, 1)
    print(" -> LCP Congigure-Ack")
    sendp(config_ack, iface=interface)

    # send Configure-Request IPCP
    configure_ack_ipcp = create_packet_ipcp_config(dst, sessionid, 0x01, 0x01, "0.0.0.0")
    print(" -> IPCP Configure-Request")
    packets = send_and_recv(interface, configure_ack_ipcp)

    # get Configure-Nak IPCP
    print(" <- {0} packet(s)".format(len(packets)))
    configure_nak_ipcp = find_packet_ppp_ipcp(packets, 0x03)
    if configure_nak_ipcp is None:
        return False

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

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
       return False

    return True

# Test ppp_11
#  - test: Test name
#  - interface: Client interface
def run_ppp_11(test, interface):
    """
    Try send wrong sessionid in lcp and ipcp lvl
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: establish pppoed -> send lcp Configuration Request [wrong sessionid] -> no reply"
        "-> establish lcp [right sessionid] -> send ipcp configuration request [wrong sessionid] -> no reply"
        "-> send ipcp configuration request [right sessionid] -> recv ipcp configuration nak"
        " -> no reply".format(test, interface)
    )
    
    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request with wrong sessionid
    config_request = create_packet_lcp_config(dst, sessionid + 1, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request [bad id]")
    packets = send_and_recv(interface, config_request)

    # get configure-ack
    print(" <- {0} packet(s)".format(len(packets)))
    configure_ack = find_packet_ppp_lcp(packets, 0x02)
    if (configure_ack is None):
        return None

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if (configure_req is None):
        return None

    # send configure-ack
    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack)

    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if(echo_req is None):
        return False

    # no more packets
    packets.remove(echo_req)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    # send Configure-Request IPCP with wrong sessionid
    configure_ack_ipcp = create_packet_ipcp_config(dst, sessionid + 1, 0x01, 0x01, "0.0.0.0")
    print(" -> IPCP Configure-Request [bad id]")
    packets = send_and_recv(interface, configure_ack_ipcp)

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    # send Configure-Request IPCP with right sessionid
    configure_ack_ipcp = create_packet_ipcp_config(dst, sessionid, 0x01, 0x01, "0.0.0.0")
    print(" -> IPCP Configure-Request")
    packets = send_and_recv(interface, configure_ack_ipcp)

    # get ipcp configuration nak
    print(" <- {0} packet(s)".format(len(packets)))
    configure_nak_ipcp = find_packet_ppp_ipcp(packets, 0x03)
    if configure_nak_ipcp is None:
        return False

    # no reply
    packets.remove(configure_nak_ipcp)
    print(" <- {0} packet(s)".format(len(packets)))
    if len(packets) > 0:
        return False

    return True

def run_ppp_12(test, interface):
    """
    Establish pppoe session and ping from client
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """
    print(
        "{0} [{1}]: send Configuration-Request_ipcp -> recv Configuration-nak_ipcp -> send Configuration-Request_ipcp"
        "-> recv Configuration-Ack_ipcp -> recv Configuration-Request_ipcp -> send Configuration-Ack_ipcp ->"
        "-> send ping request".format(test, interface)
    )

    # establish pppoe session
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

    # send configure-ack
    config_ack = create_packet_lcp_config(dst, sessionid, 0x02, configure_req[PPP_LCP].id, 512, 1)
    print(" -> LCP Congigure-Ack")
    sendp(config_ack, iface=interface)

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

    # no reply
    print(" <- {0} packet(s)".format(len(packets)))
    if (len(packets) > 0):
        return False

    # send ping request
    ping_request = create_ping_request(dst, sessionid, ip_addr)
    print(" -> ICMP Request")
    packets = send_and_recv(interface, ping_request)

    # get ping reply
    print(" <- {0} packet(s)".format(len(packets)))

    return True

# Test ppp_13
#  - test: Test name
#  - interface: Client interface
def run_ppp_13(test, interface):
    """
    Check Echo-Reply from router
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """

    print(
        "{0} [{1}]: send Configure-Request -> recv Configure-Ack -> recv Configure-Request -> send Echo-Request ->"
        " no reply".format(test, interface)
    )
    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if (pads == None):
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
    if (configure_ack is None):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if (configure_req is None):
        return False

    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack)

    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if(echo_req is None):
        return False

    # no more packets
    packets.remove(echo_req)
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    # send echo-reply
    echo_reply = create_packet_lcp_config_pkt2(echo_req, 0x0a)
    print(" -> Echo Reply")
    packets = send_and_recv(interface, echo_reply)

    # no more packets
    print(" <- {0} packet(s)".format(len(packets)))
    if(len(packets) > 0):
        return False

    return True

def run_ppp_14(test, interface):
    """
    Check ppp max-echo (2)
    Check ppp max-termination (2)
    Check ppp timeout-echo (1)
    Check ppp timeout-termination (2)
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """

    print(
        "{0} [{1}]: established session -> recv Echo-request(1) -> wait 1 sec -> recv Echo-request(2) -> wait 1 sec ->"
        "-> recv Echo-request(3) -> recv Termination-Request".format(test, interface)
    )

    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if (pads == None):
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
    if (configure_ack is None):
        return False

    # get configure-request
    packets.remove(configure_ack)
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if (configure_req is None):
        return False

    configure_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    packets = send_and_recv(interface, configure_ack, wait=0.7)

    # echo request
    print(" <- {0} packet(s)".format(len(packets)))
    echo_req = find_packet_ppp_lcp(packets, 0x09)
    if echo_req is None:
        return False

    print(" <- Wait next Echo Request(2) time to wait: 1 sec.")

    # get next echo request
    echo_req = sniff_int(interface, 0x09)
    if echo_req is None:
        return False

    print(" <- Wait next Echo Request(3) time to wait: 1 sec.")

    # get next echo request
    echo_req = sniff_int(interface, 0x09)
    if echo_req is None:
        return False

    print(" <- Wait Termination Request(1) time to wait: 2 sec.")

    # get termination request
    term_req = sniff_int(interface, 0x05, wait=2)
    if term_req is None:
        return False

    print(" <- Wait Termination Request(2) time to wait: 2 sec.")

    # get termination request
    term_req = sniff_int(interface, 0x05, wait=2)
    if term_req is None:
        return False

    # no more packets
    term_req = sniff_int(interface, 0x05, wait=2)
    if term_req:
        return False

    return True


def run_ppp_15(test, interface):
    """
    Check ppp max-configure (3)
    :param test: Test name
    :param interface: Client interface
    :return: True or False
    """

    print(
       "{0} [{1}]: send Configure-Request -> recv Configure-Ack -> recv Configure-Request -> no answer"
       " -> recv Configure-Request(1) -> no answer -> recv Configure-Request(2) -> no answer"
       " -> recv Configure-Request(3) -> no answer -> recv Termination-Request".format(test, interface)
    )

    # establish pppoe session
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

    print(" <- Wait next Configure Request(2) time to wait: 2 sec.")

    configure_req = sniff_int(interface, 0x01, wait=2)
    if configure_req is None:
        return False

    print(" <- Wait next Configure Request(3) time to wait: 2 sec.")

    configure_req = sniff_int(interface, 0x01, wait=2)
    if configure_req is None:
        return False

    print(" <- Wait Termination Request time to wait: 2 sec.")

    # get termination request
    term_req = sniff_int(interface, 0x05, wait=2)
    if term_req is None:
        return False

    return True


def run_ppp_16(test, interface):
    """

    :param test:
    :param interface:
    :return:
    """

    print(
       "{0} [{1}]: send Configure-Request[mru = 900] -> recv Configure-Nak -> send Configure-Request[mru = 900]"
       "-> recv Configure-Nak -> send Configure-Request[mru = 900] -> recv Termination-Request".format(test, interface)
    )

    # establish pppoe session
    pads = establish_pppoe_session(test, interface, 'ololo')
    if pads == None:
        return False

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request[mru = 900]
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 900, 1)
    print(" -> LCP Congigure-Request[mru = 900](1)")
    packets = send_and_recv(interface, config_request)

    # get configure-nak
    print(" <- {0} packet(s)".format(len(packets)))
    configure_nak = find_packet_ppp_lcp(packets, 0x03)
    if configure_nak is None:
        return False

    # send configure-request[mru = 900]
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 900, 1)
    print(" -> LCP Congigure-Request[mru = 900](2)")
    packets = send_and_recv(interface, config_request)

    # get configure-nak
    print(" <- {0} packet(s)".format(len(packets)))
    configure_nak = find_packet_ppp_lcp(packets, 0x03)
    if configure_nak is None:
        return False

    # send configure-request[mru = 900]
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 900, 1)
    print(" -> LCP Congigure-Request[mru = 900](3)")
    packets = send_and_recv(interface, config_request)

    # get termination request
    print(" <- {0} packet(s)".format(len(packets)))
    termination_req = find_packet_ppp_lcp(packets, 0x04)
    if termination_req is None:
        return False

    return True


from collections import OrderedDict


def register(testdict):
    testdict.update({'ppp_00': run_ppp_00})
    testdict.update({'ppp_01': run_ppp_01})
    testdict.update({'ppp_02': run_ppp_02})
    testdict.update({'ppp_03': run_ppp_03})
    testdict.update({'ppp_04': run_ppp_04})
    testdict.update({'ppp_05': run_ppp_05})
    testdict.update({'ppp_06': run_ppp_06})
    testdict.update({'ppp_07': run_ppp_07})
    testdict.update({'ppp_08': run_ppp_08})
    testdict.update({'ppp_09': run_ppp_09})
    testdict.update({'ppp_10': run_ppp_10})
    testdict.update({'ppp_11': run_ppp_11})
    # testdict.update({'ppp_12': run_ppp_12})  # do not uncomment
    testdict.update({'ppp_13': run_ppp_13})
    testdict.update({'ppp_14': run_ppp_14})
    testdict.update({'ppp_15': run_ppp_15})
    testdict.update({'ppp_16': run_ppp_16})
