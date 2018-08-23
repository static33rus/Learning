#!/usr/bin/python3.5
"""
Process which create PADI packets and send it (1)
Process which get packets from interface, and parse packets (2)
PPPOED - proc_first_parse (3)
LCP - proc_second_parse (4)
IPCP - proc_first_parse (3)
"""
from socket import *
import pcapy
import json
from scapy.all import *
from multiprocessing import Process
from optparse import OptionParser
from functools import partial
import sys
import time
import collections
import signal


class Interface:

    # data = {}
    ip_and_ses = {}
    ses_and_pas = {}

    counter_padi = 0
    counter_pado = 0
    counter_padr = 0
    counter_pads = 0
    counter_padt = 0

    counter_lcp_configuration_req_send = 0

    counter_ipcp_configuration_req_send = 0
    counter_ipcp_configuration_ack_send = 0
    counter_ipcp_configuration_req_recv = 0
    counter_ipcp_configuration_ack_recv = 0
    counter_ipcp_configuration_nak_recv = 0

    counter_lcp_configuration_req_recv = 0
    counter_lcp_configuration_ack_recv = 0
    counter_lcp_configuration_nak_recv = 0
    counter_lcp_configuration_reject_recv = 0
    counter_lcp_termination_request_recv = 0
    counter_lcp_termination_reply_recv = 0
    counter_lcp_code_reject_recv = 0
    counter_lcp_protocol_reject_recv = 0
    counter_lcp_echo_request_recv = 0
    counter_lcp_echo_reply_recv = 0

    counter_lcp_configuration_ack_send = 0
    counter_lcp_configuration_nak_send = 0
    counter_lcp_configuration_reject_send = 0
    counter_lcp_termination_request_send = 0
    counter_lcp_termination_reply_send = 0
    counter_lcp_code_reject_send = 0
    counter_lcp_protocol_reject_send = 0
    counter_lcp_echo_request_send = 0
    counter_lcp_echo_reply_send = 0

    counter_chap_challenge_recv = 0
    counter_chap_answer_send = 0
    counter_pap_authenticate_req_send = 0

    def __init__(self, dev, info_pkts):
        self.dev = dev
        self.s = socket.socket(AF_PACKET, SOCK_RAW)
        self.open = open(info_pkts+'.json', 'w')
        self.nopen = open(info_pkts+'_pass.json', 'w')
        self.counters = []

    def start_listing(self):
        self.s.bind((self.dev, 0))

    def send_packet(self, packet):
        self.s.send(packet)

    def stop_listing(self):
        self.s.close()
        sys.exit(0)

    def write_file(self, line):
        try:
            json.dump(line, self.open)
        except ValueError:
            print("I/O operation on closed file.")

    def write_file_nopen(self, line):
        try:
            json.dump(line, self.nopen)
        except ValueError:
            print("I/O operation on closed file.")

    def close_file(self):
        self.open.close()

    def close_file_nopen(self):
        self.nopen.close()

    def add_counters(self, name):
        self.counters.append(name)

    def print_counters(self):
        c = collections.Counter()
        for word in self.counters:
            c[word] += 1

        for key in c:
            print("%s -> %s" % (key, c[key]))


# HELP DEF


def get_next_mac(mac_count):
    """
    create random mac addr
    :param mac_count: counter
    :return: mac address in bytes
    """
    mac = b'\x78\x8a' + mac_count.to_bytes(4, byteorder='big')
    return mac


def get_next_hu():
    """
    create random PPPoED tag Host-Uniq
    :return: Host-Uniq in bytes
    """
    d = partial(random.randint, 0, 15)
    return b'%0x%0x%0x%0x' % (d(), d(), d(), d())


def random_magic_number():
    """
    create random magic number
    :return: magic number in bytes
    """
    m = partial(random.randint, 0, 255)
    return b'%02x%02x' % (m(), m())


def cut_packet(packet):
    """
    Take packet with less \x00 in the end
    last 2 bytes it is real len packet
    recoding last 2 bytes to int
    cut packet by this len
    for example:
        take packet: b'x\x8a\x00\x00\x00\x01\x1c\x87v@\xe4\x02\x88c\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c'
        last 2 bytes: \x00\x0c == 12
        packet: packet[:12] ==   b'x\x8a\x00\x00\x00\x01\x1c\x87v@\xe4\x02\x88c\x11\

    :param packet: packet
    :return: packet
    """
    len_packet_byte = packet[-2:]
    len_packet = int.from_bytes(len_packet_byte, byteorder='big')
    packet = packet[:len_packet]
    return packet


def pppoed_tags(packet):
    """
    parse tags from pkt
    :param packet: packet
    :return: dict with tags
    """
    host_uniq_header = b'\x01\x03\x00\x04'
    ac_cookie_header = b'\x01\x04\x00\x10'
    ac_name_header = b'\x01\x02\x00\x02'
    service_name_header = b'\x01\x01\x00\x05'

    tags = packet[20:]
    have_tags = {}

    if host_uniq_header in tags:
        hu = tags.split(host_uniq_header)[1]
        hostUniq_b = hu[:4]
        have_tags[b'\x01\x03\x00\x04'] = hostUniq_b

    if ac_cookie_header in tags:
        ac = tags.split(ac_cookie_header)[1]
        ac_cookie_b = ac[:16]
        have_tags[b'\x01\x04\x00\x10'] = ac_cookie_b

    if ac_name_header in tags:
        an = tags.split(ac_name_header)[1]
        ac_name_b = an[:2]  # AC-Name must be 'R1'
        have_tags[b'\x01\x02\x00\x02'] = ac_name_b

    if service_name_header in tags:
        sn = tags.split(service_name_header)[1]
        service_name_b = sn[:5]  # Service-Name must be 'ololo'
        have_tags[b'\x01\x01\x00\x05'] = service_name_b

    return have_tags


def len_tags(tags):
    """
    count len pppoed tags
    :param tags: pppoed tags
    :return: len tags
    """
    pppoe_tags = b''
    for key in tags:

        # if tags.get(key) is not None and key != b'\x01\x02\x00\x02':
        if tags.get(key) is not None:
            pppoe_tags += key + tags.get(key)

    len_tags = len(pppoe_tags)

    return len_tags, pppoe_tags


def check_options(packet):
    """
    check options LCP Configuration Request by len
    len(packet) = 40 bytes - pap auth
    if packet 40 bytes return True
    else return False
    :param packet: packet
    :return: None
    """
    if b'\xc0\x23' in packet:  # PAP
        return True

    return False


def get_packet_info(packet, work_with_interface, stop=False):
    """
    parse packet
    take src, dst mac
    session id
    ipcp options types:
        \x01 - IP-Addresses
        \x02 - IP-Compression-Protocol
        \x03 - IP-Address
    :param packet: packet
    :param work_with_interface: class
    :param stop: how many session established
    :return: file with info packet
    """
    # dst = packet[:6]  # this value need if we need mac address src and dst(in str)
    # src = packet[6:12]  # this value need if we need mac address src and dst(in str)
    # dst_str = dst.hex()  # this value need if we need mac address src and dst(in str) [182-187]
    # src_str = src.hex()  # this value need if we need mac address src and dst(in str) [182-187]

    # def str_to_mac(line):  # this def need if we need mac address src and dst(in str) [182-187]
    #     res = [''.join(line[::-1][i:i+2])[::-1] for i in range(0, len(line), 2)]
    #     return ':'.join(res[::-1])  # this value need if we need mac address src and dst(in str)

    sessionid = packet[16:18]
    dst = packet[:6]
    type_option = packet[26:27]

    if type_option == b'\x03':  # IPCP Option IP-Address

        ipaddr = packet[28:32]

        ipa = []
        point = '.'

        for smb in range(0, len(ipaddr)):  # make from ip address in bytes (\xc0\xa8\x0a\x01)
            ipa.append(str(ipaddr[smb]))  # string like (xx.xx.xx.xx)

        if stop is False:  # while establish no all sessions just upgrade dict
            work_with_interface.ip_and_ses[point.join(ipa)] = sessionid.hex()
            work_with_interface.ses_and_pas[sessionid.hex()] = "admin" + dst[2:].hex()

        else:  # when all sessions establish write dict to json file
            work_with_interface.ip_and_ses[point.join(ipa)] = sessionid.hex()
            work_with_interface.write_file(work_with_interface.ip_and_ses)
            work_with_interface.close_file()
            work_with_interface.ses_and_pas[sessionid.hex()] = "admin" + dst[2:].hex()
            work_with_interface.write_file_nopen(work_with_interface.ses_and_pas)
            work_with_interface.close_file_nopen()

    else:
        print("     >>> Packet do not have ipcp IP-Address option\n")
        print("     >>> Type first option: {}\n".format(type_option))


def close_socket():
    """
    send b'\x00' packet with client mac src and dst
    :return: None
    """
    dst = b'\x78\x8a\x00\x00\x00\x00'
    src = b'\x78\x8a\x00\x00\x00\x00'

    packet = dst + src + b'\x88\x63' + (b'\x00' * 86)

    work_with_interface.send_packet(packet)


def handler(signum, frame):
    print("\n\nExit")
    raise Exception("end of time")


# MAIN DEF


def create_packet_padi(mac_count, work_with_interface, details):
    """
    create packet padi (in bytes)
    :param work_with_interface: class
    :param mac_count: how many mac address need send
    :return: None
    """
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    tags_header = b'\x01\x01\x00\x00\x01\x03\x00\x04'

    padis = 0

    try:
        mac = int(mac_count)

        for i in range(0, mac):
            eth_lvl = dst_mac + get_next_mac(i) + b'\x88\x63'
            pppoed_lvl = b'\x11' + b'\x09' + b'\x00\x00' + b'\x00\x0c'
            pppoed_tags = tags_header + get_next_hu()

            # Create packet padi
            packet = eth_lvl + pppoed_lvl + pppoed_tags
            padis += 1

            if padis > 1000:
                time.sleep(0.02)
                padis = 0

            # send packet
            work_with_interface.send_packet(packet)
            work_with_interface.counter_padi += 1
            work_with_interface.add_counters("PADI")

        if details is True:
            work_with_interface.print_counters()
        sys.exit(0)

    except TypeError:
        print("     >>> mac_count must be integer, not string")
        sys.exit(1)


def get_next_packet(dev, echo, work, mac_count):
    """
    Get packets from dev
    Check, if this packet have client dst=mac address take it
    Parse this packet (pppoed/lcp/ipcp)
    Send this packet to other process
    :param dev: interface
    :param echo: get LCP echo-request or not
    :return: packet
    """
    cap = pcapy.open_live(dev, 65536, 1, 0)
    sck9091 = socket.socket()
    sck9092 = socket.socket()

    try:
        sck9091.connect(('localhost', 9091))
        sck9092.connect(('localhost', 9092))

        while True:
            (header, packet) = cap.next()

            if packet[:2] == b'x\x8a':  # this is packet from server to client

                len_need_add = 98 - len(packet)
                packet += (b'\x00' * len_need_add) + len(packet).to_bytes(2, byteorder='big')

                if packet[12:14] == b'\x88c':  # b'\x88c' - 0x8863 (pppoed) (1)
                    sck9091.send(packet)

                elif packet[12:14] == b'\x88d' and packet[20:22] == b'\xc0\x21':  # if pppoes and lcp (2)

                    if echo is not True and packet[22:23] == b'\x09':  # lcp echo-request
                        continue
                    else:
                        sck9092.send(packet)

                elif packet[12:14] == b'\x88d' and packet[20:22] == b'\xc0\x23':  # if pppoes and pap (2)
                    sck9092.send(packet)

                elif packet[12:14] == b'\x88d' and packet[20:22] == b'\xc2\x23':  # if pppoes and chap (2)
                    sck9092.send(packet)

                elif packet[12:14] == b'\x88d' and packet[20:22] == b'\x80\x21':  # if pppoes and ipcp (1)
                    sck9091.send(packet)

                elif packet[6:8] == b'x\x8a':  # finish packet, exit
                    print(packet)
                    break

    except ConnectionRefusedError:
        print("ConnectionRefusedError")
        sck9091.close()
        sck9092.close()
        sys.exit(1)

    except KeyboardInterrupt:
        print("KeyboardInterrupt")
        sck9091.close()
        sck9092.close()
        sys.exit(0)

    finally:
        sck9091.close()
        sck9092.close()
        sys.exit(0)


def first_parse(work_with_interface, mac_count, work, details):
    """
    first parse
    :param work_with_interface: class
    :param mac_count: count mac address
    :return: None
    """

    counter_establish_sessions = 0

    f_sock = socket.socket(AF_INET, SOCK_STREAM)
    f_sock.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("ii",  1, 0))

    try:
        f_sock.bind(('', 9091))
        f_sock.listen(10)

        try:
            f_conn, f_addr = f_sock.accept()
            f_conn.settimeout(1)

            while True:
                data = f_conn.recv(100)
                packet = cut_packet(data)

                dst = packet[:6]
                src = packet[6:12]

                # parse pppoed
                if packet[12:14] == b'\x88c' and packet[15:16] == b'\x07':  # PADO
                    work_with_interface.counter_pado += 1
                    work_with_interface.add_counters("PADO")
                    create_packet_padr(src, dst, packet, work_with_interface)
                    work_with_interface.add_counters("PADR")
                    work_with_interface.counter_padr += 1

                if packet[12:14] == b'\x88c' and packet[15:16] == b'\x65':  # PADS
                    work_with_interface.counter_pads += 1
                    work_with_interface.add_counters("PADS")
                    create_packet_lcp_configuration_req(src, dst, packet, work_with_interface)
                    work_with_interface.counter_lcp_configuration_req_send += 1
                    work_with_interface.add_counters("LCP Configuration Request sent")

                if packet[12:14] == b'\x88c' and packet[15:16] == b'\xa7':  # PADT
                    work_with_interface.counter_padt += 1
                work_with_interface.add_counters("PADT")

                # parse ipcp

                if packet[12:14] == b'\x88d' and packet[22:23] == b'\x01':  # IPCP configuration-request
                    work_with_interface.counter_ipcp_configuration_req_recv += 1
                    work_with_interface.add_counters("IPCP Configuration Request recv")
                    create_packet_ipcp_configuration_req_ack(src, dst, packet, b'\x02', work_with_interface)
                    work_with_interface.counter_ipcp_configuration_ack_send += 1
                    work_with_interface.add_counters("IPCP Configuration Ack sent")
                    counter_establish_sessions += 1
                    work_with_interface.add_counters("Established sessions")

                    if counter_establish_sessions == int(mac_count):
                        # print("     >>> establish sessions: {}".format(counter_establish_sessions))
                        close_socket()

                        # print("462")
                        # work_with_interface.write_file(work_with_interface.data)
                        work_with_interface.close_file()
                        work_with_interface.stop_listing()

                        f_conn.close()
                        f_sock.close()
                        break

                if packet[12:14] == b'\x88d' and packet[22:23] == b'\x02':  # IPCP configuration-ack
                    work_with_interface.counter_ipcp_configuration_ack_recv += 1
                    work_with_interface.add_counters("IPCP Configuration Ack recv")

                if packet[12:14] == b'\x88d' and packet[22:23] == b'\x03':  # IPCP configuration-nak
                    work_with_interface.counter_ipcp_configuration_nak_recv += 1
                    work_with_interface.add_counters("IPCP Configuration Nak recv")
                    create_packet_ipcp_configuration_req_ack(src, dst, packet, b'\x01', work_with_interface)
                    work_with_interface.counter_ipcp_configuration_req_send += 1
                    work_with_interface.add_counters("IPCP Configuration Request sent")

                    if work_with_interface.counter_ipcp_configuration_nak_recv < int(mac_count):
                        get_packet_info(packet, work_with_interface)  # take ip addr and session id

                    else:
                        get_packet_info(packet, work_with_interface, stop=True)  # take ip addr and session id

                if not data:
                    # print("488")
                    # work_with_interface.write_file(work_with_interface.data)
                    # work_with_interface.close_file()
                    f_conn.close()
                    f_sock.close()
                    break

        except OSError:
            # print("OSError: [Errno 98] Address already in use (1.2)")
            f_sock.close()
            # print("497")
            # work_with_interface.write_file(work_with_interface.data)
            # work_with_interface.close_file()
            sys.exit(1)

        except KeyboardInterrupt:
            print("KeyboardInterrupt (1.2)")
            f_sock.close()
            # print("504")
            # work_with_interface.write_file(work_with_interface.data)
            # work_with_interface.close_file()
            sys.exit(0)

        finally:
            # print("509")
            # work_with_interface.write_file(work_with_interface.data)
            work_with_interface.close_file()
            f_sock.close()
            sys.exit(0)

    except OSError:
        print("OSError: [Errno 98] Address already in use (1.1)")
        work_with_interface.close_file()
        f_sock.close()
        sys.exit(1)

    except KeyboardInterrupt:
        print("KeyboardInterrupt (1.1)")
        work_with_interface.close_file()
        f_sock.close()
        sys.exit(0)

    finally:
        f_sock.close()
        work_with_interface.close_file()
        if details is True:
            work_with_interface.print_counters()
            sys.exit(0)
        else:
            sys.exit(0)


def second_parse(work_with_interface, username, password, details, rex):
    """
    second parse
    :param work_with_interface: class
    :param username: username for authenticate
    :param password: password for authenticate
    :return: None
    """
    s_sock = socket.socket(AF_INET, SOCK_STREAM)
    s_sock.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("ii",  1, 0))

    try:
        s_sock.bind(('', 9092))
        s_sock.listen(10)

        try:
            s_conn, s_addr = s_sock.accept()
            s_conn.settimeout(2)

            while True:
                data = s_conn.recv(100)
                packet = cut_packet(data)

                dst = packet[:6]
                src = packet[6:12]
                sessionid = packet[16:18]

                # check -q key(quit establish)
                pkt_end = b'\x00' * 100
                if packet == pkt_end:
                    print("     >>> have end packet")
                    s_conn.send(pkt_end)

                    s_conn.close()
                    work_with_interface.close_file()
                    s_sock.close()
                    sys.exit(0)

                # parse LCP
                if packet[22:23] == b'\x01':  # LCP Configuration-request
                    work_with_interface.counter_lcp_configuration_req_recv += 1
                    work_with_interface.add_counters("LCP Configuration Request recv")
                    check_pap = check_options(packet)

                    if check_pap:  # Create LCP Configuration-ack then create PAP authenticate-request
                        create_packet_lcp_configuration_ack(src, dst, packet, work_with_interface)
                        work_with_interface.counter_lcp_configuration_ack_send += 1
                        work_with_interface.add_counters("LCP Configuration Ack sent")

                        if rex is not True:
                            create_pap_authenticate_req_different_lp(src, dst, sessionid, work_with_interface)
                            work_with_interface.counter_pap_authenticate_req_send += 1
                            work_with_interface.add_counters("PAP Authenticate Request sent")

                        else:
                            create_packet_pap_authenticate_req(
                                src, dst, sessionid, username, password, work_with_interface
                            )
                            work_with_interface.counter_pap_authenticate_req_send += 1
                            work_with_interface.add_counters("PAP Authenticate Request sent")

                    else:  # Create only LCP Configuration-ack then IPCP Configuration-req
                        create_packet_lcp_configuration_ack(src, dst, packet, work_with_interface)
                        work_with_interface.counter_lcp_configuration_ack_send += 1
                        work_with_interface.add_counters("LCP Configuration Ack sent")

                        create_packet_ipcp_configuration_req(src, dst, packet, work_with_interface)
                        work_with_interface.counter_ipcp_configuration_req_send += 1
                        work_with_interface.add_counters("IPCP Configuration Request sent")

                if packet[20:22] == b'\xc0\x23' and packet[22:23] == b'\x02':  # PAP authenticate-ack
                    create_packet_ipcp_configuration_req(src, dst, packet, work_with_interface)
                    work_with_interface.counter_ipcp_configuration_req_send += 1
                    work_with_interface.add_counters("IPCP Configuration Request sent")

                if packet[20:22] == b'\xc0\x23' and packet[22:23] == b'\x03':  # PAP authenticate-nak
                    print("     >>> Authenticate PAP failure")

                if packet[20:22] == b'\xc2\x23':  # CHAP Challenge
                    work_with_interface.counter_chap_challenge_recv += 1
                    work_with_interface.add_counters("CHAP Challenge recv")
                    create_packet_chap_answer(src, dst, sessionid, packet, username, password, work_with_interface)
                    work_with_interface.counter_chap_answer_send += 1
                    work_with_interface.add_counters("CHAP Answer recvsent")

                if packet[22:23] == b'\x02':  # LCP Configuration-ack
                    work_with_interface.counter_lcp_configuration_ack_recv += 1
                    work_with_interface.add_counters("LCP Configuration Ack recv")

                if packet[22:23] == b'\x03':  # LCP Configuration-nak
                    work_with_interface.counter_lcp_configuration_nak_recv += 1
                    work_with_interface.add_counters("LCP Configuration Nak recv")

                if packet[22:23] == b'\x04':  # LCP Configuration-reject
                    work_with_interface.counter_lcp_configuration_reject_recv += 1
                    work_with_interface.add_counters("LCP Configuration Request recv")

                if packet[22:23] == b'\x05':  # LCP Termination-request
                    work_with_interface.counter_lcp_termination_request_recv += 1
                    work_with_interface.add_counters("LCP Termination Request recv")
                    create_packet_lcp_termination_rep(src, dst, packet, work_with_interface)
                    work_with_interface.counter_lcp_termination_reply_send += 1
                    work_with_interface.add_counters("LCP Termination Reply sent")

                if packet[22:23] == b'\x06':  # LCP Termination-reply
                    work_with_interface.counter_lcp_termination_reply_recv += 1
                    work_with_interface.add_counters("LCP Termination Reply recv")

                if packet[22:23] == b'\x07':  # LCP Code-reject
                    work_with_interface.counter_lcp_code_reject_recv += 1
                    work_with_interface.add_counters("LCP code reject recv")

                if packet[22:23] == b'\x08':  # LCP Protocol-reject
                    work_with_interface.counter_lcp_protocol_reject_recv += 1
                    work_with_interface.add_counters("LCP Protocol Reject recv")

                if packet[22:23] == b'\x09':  # LCP Echo-request
                    work_with_interface.counter_lcp_echo_request_recv += 1
                    work_with_interface.add_counters("LCP Echo request recv")
                    create_packet_lcp_echo_rep(src, dst, packet, work_with_interface)
                    work_with_interface.counter_lcp_echo_reply_send += 1
                    work_with_interface.add_counters("LCP Echo Reply sent")

                if packet[22:23] == b'\x0a':  # LCP Echo-reply
                    work_with_interface.counter_lcp_echo_reply_recv += 1
                    work_with_interface.add_counters("LCP Echo Reply recv")

                if not data:
                    work_with_interface.write_file(work_with_interface.ip_and_ses)
                    work_with_interface.close_file()
                    s_conn.close()
                    break

        except OSError:
            # print("OSError: [Errno 98] Address already in use (2.2)")
            work_with_interface.close_file()
            s_sock.close()
            sys.exit(1)

        except KeyboardInterrupt:
            print("KeyboardInterrupt (2.2)")
            work_with_interface.close_file()
            s_sock.close()
            sys.exit(0)

        finally:
            work_with_interface.close_file()
            s_sock.close()

    except OSError:
            print("OSError: [Errno 98] Address already in use (2.1)")
            work_with_interface.close_file()
            s_sock.close()
            sys.exit(1)

    except KeyboardInterrupt:
        print("KeyboardInterrupt (2.1)")
        work_with_interface.close_file()
        s_sock.close()
        sys.exit(0)

    finally:
        s_sock.close()
        work_with_interface.close_file()

        if details is True:
            work_with_interface.print_counters()
            sys.exit(0)
        else:
            sys.exit(0)


# CREATE DEF


def create_packet_padr(src, dst, packet, work_with_interface):
    """
    Create packet padr from packet pado
    :param src: src mac
    :param dst: dst mac
    :param packet: pado packet
    :param work_with_interface: class
    :return: None
    """
    tags = pppoed_tags(packet)
    pppoed_len, options = len_tags(tags)

    # Create PADR packet
    packet = src+dst+b'\x88c' + b'\x11' + b'\x19' + b'\x00\x00' + (pppoed_len.to_bytes(2, byteorder='big')) + options

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_lcp_configuration_req(src, dst, packet, work_with_interface):
    """
    Create packet lcp configuration-request from packet pads
    :param src: src mac
    :param dst: dst mac
    :param packet: pads packet
    :param work_with_interface: class
    :return: None
    """

    sessionid = packet[16:18]

    mru_header = b'\x01\x04'
    mru = 1492

    magic_header = b'\x05\x06'
    magic = random_magic_number()

    # Create LCP configuration-Request
    packet = src+dst+b'\x88d' + b'\x11' + b'\x00' + sessionid + b'\x00\x10' + b'\xc0\x21' + b'\x01' + b'\x01' + b'\x00\x0e'\
        + mru_header + (mru.to_bytes(2, byteorder='big')) + magic_header + magic

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_ipcp_configuration_req_ack(src, dst, packet, code, work_with_interface):
    """
    Create packet ipcp configuration-ack from
     packet ipcp configuration-request or
     ipcp configuration-nak
    :param src: src mac
    :param dst: dst mac
    :param packet: pads packet
    :param work_with_interface: class
    :return: None
    """
    sessionid = packet[16:18]
    options = packet[23:]

    # Create IPCP Configuration-Request or Configuration-Ack
    packet = src+dst+b'\x88d' + b'\x11' + b'\x00' + sessionid + b'\x00\x0c' + b'\x80\x21' + code + options

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_ipcp_configuration_req(src, dst, packet, work_with_interface):
    """
    Create packet ipcp configuration-request from
     packet ipcp configuration-ack or
     ipcp configuration-nak or
     after PAP auth
    :param src: src mac
    :param dst: dst mac
    :param packet: pads packet
    :param work_with_interface: class
    :return: None
    """
    sessionid = packet[16:18]
    options = b'\x03\x06\x00\x00\x00\x00'

    # Create IPCP Configuration-Request
    packet = src+dst+b'\x88d' + b'\x11' + b'\x00' + sessionid + b'\x00\x0c' + b'\x80\x21' + b'\x01' + b'\x01'\
        + b'\x00\x0a' + options

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_lcp_configuration_ack(src, dst, packet, work_with_interface):
    """
    Create packet lcp configuration-ack from packet lcp configuration-request
    :param src: src mac
    :param dst: dst mac
    :param packet: lcp configuration-request packet
    :param work_with_interface: class
    :return: None
    """
    # Create LCP Configuration-ack
    packet = src + dst + packet[12:22] + b'\x02' + packet[23:]

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_lcp_termination_rep(src, dst, packet, work_with_interface):
    """
    Create packet lcp termination-reply from packet lcp termination-request
    :param src: src mac
    :param dst: dst mac
    :param packet: lcp configuration-request packet
    :param work_with_interface: class
    :return: None
    """
    # Create LCP Termination-reply
    packet = src + dst + packet[12:22] + b'\x06' + packet[23:]

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_lcp_echo_rep(src, dst, packet, work_with_interface):
    """
    Create packet lcp echo-reply from packet lcp echo-request
    :param src: src mac
    :param dst: dst mac
    :param packet: lcp configuration-request packet
    :param work_with_interface: class
    :return: None
    """
    # Create LCP Echo-reply
    packet = src + dst + packet[12:22] + b'\x0a' + packet[23:]

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_pap_authenticate_req(src, dst, sessionid, username, password, work_with_interface):
    """
    Create packet pap authenticate request
    :param src: src mac
    :param dst: dst mac
    :param sessionid: session id
    :param username: username for authenticate
    :param password: password for authenticate
    :param work_with_interface: class
    :return: None
    """

    # Create PPP PAP
    pap_data = len(username).to_bytes(1, byteorder='big') + username.encode('utf-8')\
        + len(password).to_bytes(1, byteorder='big') + password.encode('utf-8')

    # Check len pap data
    len_pap_data = len(pap_data) + 4  # 4 bytes it is: code(1b) + id(1b) + len(2b)

    # Create PPP
    ppp_pap = b'\x01' + b'\x01' + len_pap_data.to_bytes(2, byteorder='big') + pap_data

    # Create PPPoES
    pppoes = b'\x11' + b'\x00' + sessionid + len(b'\xc0\x23' + ppp_pap).to_bytes(2, byteorder='big')

    # Create full packet
    packet = src + dst + b'\x88d' + pppoes + b'\xc0\x23' + ppp_pap

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_pap_authenticate_req_different_lp(src, dst, sessionid, work_with_interface):
    """
    This def need for TRex tests (key -r)
    for every mac change username and password
    Ex: for mac 78:8a:00:00:00:00 password: admin00000000
        for mac 78:8a:00:00:00:01 password: admin00000001
        for mac 78:8a:12:34:56:78 password: admin12345678
    :param src: src mac
    :param dst: dst mac
    :param sessionid: session id
    :param work_with_interface: class
    :return: None
    """

    username = "admin" + dst[2:].hex()
    password = "admin" + dst[2:].hex()

    # Create PPP PAP
    pap_data = len(username).to_bytes(1, byteorder='big') + username.encode('utf-8')\
        + len(password).to_bytes(1, byteorder='big') + password.encode('utf-8')

    # Check len pap data
    len_pap_data = len(pap_data) + 4  # 4 bytes it is: code(1b) + id(1b) + len(2b)

    # Create PPP
    ppp_pap = b'\x01' + b'\x01' + len_pap_data.to_bytes(2, byteorder='big') + pap_data

    # Create PPPoES
    pppoes = b'\x11' + b'\x00' + sessionid + len(b'\xc0\x23' + ppp_pap).to_bytes(2, byteorder='big')

    # Create full packet
    packet = src + dst + b'\x88d' + pppoes + b'\xc0\x23' + ppp_pap

    # Send packet
    work_with_interface.send_packet(packet)

    return None


def create_packet_chap_answer(src, dst, sessionid, packet, username, password, work_with_interface):
    """
    IT IS DOES NOT WORK YET!!!!(((
    Create packet chap answer
    :param src: src mac
    :param dst: dst mac
    :param sessionid: session id
    :param packet: lcp configuration-request packet
    :param username: username for authenticate
    :param password: password for authenticate
    :param work_with_interface: class
    :return: None
    """
    # Challenge
    challenge_len = packet[26:27]
    challenge = packet[27:27 + challenge_len[0]]

    chap_id = packet[23:24]

    # Create autohash
    auth_hash_data = packet[23:24] + password.encode('utf-8') + challenge
    auth_hash = hashlib.md5(auth_hash_data).digest()

    # Check response len
    response_len = len(auth_hash + username.encode('utf-8')) + 5

    # Create packet
    packet = src + dst + b'\x88d' + b'\x11' + b'\x00' + sessionid + b'\x00\x1c' + b'\xc2\x23' + \
        b'\x02' + chap_id + b'\x00' + bytes([response_len]) + b'\x10' + auth_hash + username.encode('utf-8')

    # Send packet
    work_with_interface.send_packet(packet)

    return None


# MAIN


def main(mac_count, dev, username, password, echo, work, details, timer, rex, work_with_interface):
    """
    start process
    :param mac_count: how many mac address
    :param dev: interface
    :param username: username for authenticate
    :param password: password for authenticate
    :param echo: send echo-reply or not
    :param work: work after establish sessions
    :param details: show counters pppoed and pppoes packets
    :param timer: exit from script after (n) sec.
    :param rex:
    :param work_with_interface: class
    :return: None
    """

    proc_padi = Process(
            target=create_packet_padi, args=(mac_count, work_with_interface, details,)
    )  # create and send padi

    proc_take_packets = Process(
            target=get_next_packet, args=(dev, echo, work, mac_count,)
    )  # take packets from server

    proc_first_parse = Process(
            target=first_parse, args=(work_with_interface, mac_count, work, details,)
    )  # pppoed & ipcp

    proc_second_parse = Process(
            target=second_parse, args=(work_with_interface, username, password, details, rex,)
    )  # lcp

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(int(timer))

    try:
        proc_first_parse.start()
        proc_second_parse.start()
        time.sleep(0.5)
        proc_take_packets.start()
        time.sleep(0.1)
        proc_padi.start()

    except Exception as exc:
        print(exc)

    except KeyboardInterrupt:
        proc_first_parse.terminate()
        proc_second_parse.terminate()
        proc_padi.terminate()
        proc_take_packets.terminate()
        work_with_interface.close_file()


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option(
        "-c", "--count", dest="count", default=2, help="count mac address clients"
    )
    parser.add_option(
        "-i", "--interface", dest="interface", default="veth0", help="interface to pppoe server"
    )
    parser.add_option(
        "-u", "--username", dest="username", default="admin", help="username for authenticate"
    )
    parser.add_option(
        "-p", "--password", dest="password", default="admin", help="password for authenticate"
    )
    parser.add_option(
        "-f", "--file", dest="file", default="packet_info", help="file with src,dst,sessionid client"
    )
    parser.add_option(
        "-e", "--echo", dest="echo", default=True, help="send echo-request or not(default True)"
    )
    parser.add_option(
        "-w", "--work", dest="work", default=True, help="work after establish sessions(default True)"
    )
    parser.add_option(
        "-d", "--details", dest="details", default=True, help="show counter pppoed and pppoes packets"
    )
    parser.add_option(
        "-t", "--timer", dest="timer", default=10, help="exit from script after (n) sec.(default 10 sec.)"
    )
    parser.add_option(
        "-r", "--rex", dest="rex", default=True, help="false if need PAP with password: admin+last 4 bytes of mac(TRex)"
    )
    (options, args) = parser.parse_args()

    work_with_interface = Interface(options.interface, options.file)
    work_with_interface.start_listing()

    main(
        options.count,
        options.interface,
        options.username,
        options.password,
        options.echo,
        options.work,
        options.details,
        options.timer,
        options.rex,
        work_with_interface
    )

    work_with_interface.stop_listing()
    sys.exit()
