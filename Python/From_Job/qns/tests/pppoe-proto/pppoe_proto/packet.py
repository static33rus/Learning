#!/usr/bin/python3

######################
# packet management
######################

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import hashlib


def send_and_recv(interface, packet, wait=0.1):
    """
    Send packet and return array of received packets array
    :param interface: Client interface
    :param packet: Packet to send
    :param wait: how many sec wait answer packets (default 0. sec)
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
    Find PPPoED packet by code in received packets
    :param packets: Received packets
    :param code: Packet code
    :return: None
    """
    i = 0
    for packet in packets:
        if(packet[Ether].type == 0x8863):
            print("    >>> PPPOED PACKET[{0}] code {1}".format(i, packet[PPPoED].code));
            for tag in packet[PPPoED].tags:
                if (tag.type != 0):
                    print("        {0} : {1}".format(tag.type, tag.data));
            if(packet[PPPoED].code == code):
                return packet
        else:
            print("    >>> ETHERNET PACKET[{0}]: {1}".format(i, packet[Ether].type));

        i = i + 1

    return None


def check_auth_proto(option, code):
    """
    Check code Authentication protocol
    :param option: LCP option with auth proto
    :param code: code auth protocol
    PAP: 0xc023
    CHAP: 0xc223
    :return: True or False
    """
    if option.data == code:
        return True
    return False


def find_lcp_option(lcp, type):
    """
    Search LCP option with Authentication Protocol
    :param lcp: LCP options from packet
    :param type: type option (3 = Authentication Protocol)
    :return: None or option
    """
    for option in lcp.options:
        if option.type == type:
            return option
    return None


def find_packet_ppp_lcp(packets, code):
    """
    Find PPP LCP packet by code in received packets
    :param packets: Received packets
    :param code: Packet code
    :param check_auth: Check autenticate info in packet options
    :return: None of packet
    """
    i = 0
    for packet in packets:
        if(packet[Ether].type == 0x8864):
            print("    >>> PPP PACKET[{0}] proto {1}".format(i, packet[PPP].proto))
            if(packet[PPP].proto == 0xc021):
                print("        LCP code {:02x}".format(packet[PPP_LCP].code))
                if(packet[PPP_LCP].code >= 0x01 and packet[PPP_LCP].code <= 0x04):
                    for option in packet[PPP_LCP].options:
                        if (option.type != 0):
                            print("        {0} : {1}".format(option.type, option.data))
                if(packet[PPP_LCP].code == code):
                    return packet

            if packet[PPP].proto == 0xc023:  # PAP[0xc023]
                print("        PAP code {}".format(packet[Raw].load[:1]))
                if int(''.join([ascii(x) for x in (packet[Raw].load[:1])])) == code:
                    return packet

            if packet[PPP].proto == 0xc223:  # CHAP[0xc223]
                print("        CHAP code {}".format(packet[Raw].load[:1]))
                if int(''.join([ascii(x) for x in (packet[Raw].load[:1])])) == code:
                    return packet

        else:
            print("    >>> ETHERNET PACKET[{0}]: {1}".format(i, packet[Ether].type))

        i += 1

    return None

def find_packet_ppp_ipcp(packets, code):
    """
    Find PPP IPCP packet by code in received packets
    :param packets: Received packets
    :param code: Packet code
    :return: None
    """
    i = 0
    for packet in packets:
        if(packet[Ether].type == 0x8864):
            print("    >>> PPP PACKET[{0}] proto {1}".format(i, packet[PPP].proto))
            if packet[PPP].proto == 0x8021:
                print("        IPCP code {:02x}".format(packet[PPP_IPCP].code))
                if packet[PPP_IPCP].options != None:
                    for option in packet[PPP_IPCP].options:
                        if option.type != 0:
                            print("        {0} : {1}".format(option.type, option.data))
                if packet[PPP_IPCP].code == code:
                    return packet
        else:
            print("    >>> ETHERNET PACKET[{0}]: {1}".format(i, packet[Ether].type))

        i += 1

    return None


def find_ipcp_option(ipcp, type):
    """
    Search LCP option with Authentication Protocol
    :param ipcp: IPCP options from packet
    :param type: type option
    :return: None or option
    """
    for option in ipcp.options:
        if option.type == type:
            return option
    return None


def validate_lcp_options(options, mru):
    """
    Validate LCP options
    :param options: LCP options
    :param mru: MRU value
    :return: True or False
    """
    opt_mru = None;
    for option in options:
        if(option.type == 0x01):
            if(mru != None):
                opt_mru = option.data
                imru = int(opt_mru);
                if(imru != mru):
                    return False
    if(mru != None):
        if(opt_mru == None):
            return False

    return True


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


def create_packet_padr(dst, accookie, acname, service):
    """
    Create PADR packet
    :param dst: Destination MAC
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

    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8863) / \
        PPPoED(version=1, type=1, code=0x19, sessionid=0x0000, tags=tags)
    return packet


def create_packet_padt(dst, sessionid, accookie, error):
    """
    Create PADT packet
    :param dst: Destination MAC
    :param sessionid: PPPoE session id
    :return: packet
    """
    tags=[]

    tags.append(PPPoE_Tag(type='Host-Uniq', data=b'\x08\xf4\x18\x35\x80\xff\xff\xff'))

    if accookie != None:
        tags.append(PPPoE_Tag(type='AC-Cookie', data=accookie))

    if error != None:
        tags.append(PPPoE_Tag(type=0x203, data=error))

    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8863) / \
        PPPoED(version=1, type=1, code=0xa7, sessionid=sessionid, tags=tags)
    return packet


def create_packet_lcp_config(dst, sessionid, code, id, mru, magic):
    """
    Create LCP Config-Request packet
    :param dst: Destination MAC
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

    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0xc021) / \
        PPP_LCP(code=code, id=id, options=options)
    return packet

# Create LCP configure packet by another packet
#  - source: Source packet
#  - code: LCP code
def create_packet_lcp_config_pkt(source, code):
    packet = Ether(dst=source[Ether].src, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=source[PPPoE].sessionid) / \
        PPP(proto=0xc021) / \
        source[PPP_LCP]
    packet[PPP_LCP].code = code
    return packet;

# Create LCP configure packet by another packet
#  - source: Source packet
#  - code: LCP code
def create_packet_lcp_config_pkt2(source, code):
    packet = Ether(dst=source[Ether].src, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=source[PPPoE].sessionid) / \
        PPP(proto=0xc021) / \
        PPP_LCP(code=code, id=source[PPP_LCP].id, magic_number=source[PPP_LCP].magic_number)
    return packet;

def create_packet_pap(dst, sessionid, username, password):
    """
    Create PAP Authenticate-Request pkt
    username = admin
    password = admin
    :param dst: Destination MAC
    :param sessionid: PPPoE session id
    :return: packet
    """

    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0xc023) / \
        Raw(load='\x01\x01\x00\x10\x05' + username + '\x05' + password)

    # \x01: code
    # \x01: id
    # \x00\x10: len(16)
    # \x05: len(username)
    # \x61\x64\x6d\x69\x6e: admin
    # \x05: len(password)
    # \x61\x64\x6d\x69\x6e: admin

    return packet


def create_packet_ipcp_config(dst, sessionid, code, id, ipaddr, p_dns=None, s_dns=None):
    """
    Create IPCP Config-Request packet
    :param dst: Destination MAC
    :param sessionid: PPPoE session id
    :param code: LCP code
    :param id: Message id
    :param ipaddr: ip address
    :return: packet
    """
    ip = str_ip_to_byte_ip(ipaddr)
    prim_dns = str_ip_to_byte_ip(p_dns)
    sec_dns = str_ip_to_byte_ip(s_dns)

    options = []
    options.append(PPP_IPCP_Option(type=0x03, data=ip))

    if prim_dns:
        options.append(PPP_IPCP_Option(type=0x81, data=prim_dns))

    if sec_dns:
        options.append(PPP_IPCP_Option(type=0x83, data=sec_dns))

    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0x8021) / \
        PPP_IPCP(code=code, id=id, options=options)
    return packet


def check_ipcp_option(option, data):
    if option.data == data:
        return True
    return None


def str_ip_to_byte_ip(ipaddr):
    """
    str ip address to byte ip address
    1. clear ipaddr from '.' symbols
    2. try convert every symbol to int and appent this symbol to list 'ipa'
    3. add every element from list 'ipa' to ip
    :param ipaddr: ip address in string
    :return: ip address in bytes
    """

    if ipaddr:
        str_to_int = re.sub('\.', '', ipaddr)
        ipa = []
        ip = b''
        for smb in str_to_int:

            try:
                ipa.append(int(smb).to_bytes(1, byteorder='big'))

            except NameError:
                print("    >>> Wrong symbol in ip address: {}".format(smb))
                return None

        for i in range(0, len(ipa)):
            ip += ipa[i]

        return ip
    else:
        return None

def create_packet_ipcp_config_pkt(source, code, sessionid):
    """
    Create IPCP configure packet by another packet
    :param source: Source packet
    :param code: LCP code
    :param sessionid: PPPoE session id
    :return: packet
    """
    packet = Ether(dst=source[Ether].src, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0x8021) / \
        source[PPP_IPCP]
    packet[PPP_IPCP].code = code
    return packet


def create_packet_echo_request(dst, sessionid, code, id, magic):
    """
    Create Echo-Request packet
    :param dst: Destination MAC
    :param sessionid: PPPoE session id
    :param code: LCP code
    :param id: Message id
    :param magic: Magic value
    :return: packet
    """
    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0xc021) / \
        PPP_LCP(code=code, id=id, len=8, magic_number=magic)
    return packet


def create_packet_lcp_without_options(dst, sessionid, code, id, length):
    """
    Create LCP packet without options
    :param dst: Destination MAC
    :param sessionid: PPPoE session id
    :param code: LCP code
    :param id: Message id
    :param length: Length
    :return: packet
    """
    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0xc021) / \
        PPP_LCP(code=code, id=id, len=length)
    return packet


def create_packet_chap_answer(dst, sessionid, source, pass_in_b):
    """
    Take info from source pkt(chap challenge)
    consider answer hash
    create chap answer pkt
    :param dst: Destination MAC
    :param sessionid: PPPoE session id
    :param source: Source packet
    :param pass_in_b: password in type bytes(b'admin')
    :return: Packet chap answer
    """

    raw_load = source[Raw].load

    chap_identifier = raw_load[1:2]
    challenge_len = raw_load[4:5]
    challenge = raw_load[5:5 + challenge_len[0]]  # challenge_len = b'\x10'; challenge_len[0] = 16
    create_auth_hash = chap_identifier + pass_in_b + challenge
    auth_hash = hashlib.md5(create_auth_hash).digest()
    response_len = len(auth_hash + b'admin') + 5

    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0xc223) / \
        Raw(
        load=b'\x02' + chap_identifier + b'\x00' + bytes([response_len]) + b'\x10' + auth_hash + b'admin'
        )

    return packet


def establish_pppoe_session(test, interface, service='ololo', wait=0.2):
    """
    Establish PPPoE session
    :param test: Test name
    :param interface: Client interface
    :param service: Service-Name tag
    :return: pads packet or None
    """
    # send padi & receive pado
    padi = create_packet_padi(service)
    print(" -> PADI")
    packets = send_and_recv(interface, padi, wait)

    # get pado
    print(" <- {0} packet(s)".format(len(packets)))
    pado = find_packet_pppoed(packets, 0x07)
    if(pado is None):
        return None

    # get AC-Cookie
    accookie = None
    for tag in pado[PPPoED].tags:
        if(tag.type == 260):
            accookie = tag.data
            break
    if(accookie == None):
        print(" AC-Cookie is not set")
        return None

    padr = create_packet_padr(pado[Ether].src, accookie, None, service)
    print(" -> PADR")
    packets = send_and_recv(interface, padr, wait)

    # get pads
    print(" <- {0} packet(s)".format(len(packets)))
    pads = find_packet_pppoed(packets, 0x65)
    if(pads is None):
        return None

    print(" Session ID: {:04x}".format(pads[PPPoED].sessionid))
    if(pads[PPPoED].sessionid == 0):
        return None

    return pads


def establish_lcp_connect(test, interface, service, wait):
    """
    Establish PPPoE session and establish LCP connect
    :param test: Test name
    :param interface: Client interface
    :param service: Service-Name tag
    :return:
    """
    # establish pppoe session
    pads = establish_pppoe_session(test, interface, service, wait)
    if (pads == None):
        return None

    dst = pads[Ether].src
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Congigure-Request")
    packets = send_and_recv(interface, config_request, wait)

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
    packets = send_and_recv(interface, configure_ack, wait)
    
    return configure_req


def create_ping_request(dst, sessionid, ip_addr):
    """
    form ping request
    :param test: Test name
    :param interface: Client interface
    :param service: Service-Name tag
    :return: ping request
    """

    packet = Ether(dst=dst, src="32:ef:21:95:12:0a", type=0x8864) / \
        PPPoE(version=1, type=1, sessionid=sessionid) / \
        PPP(proto=0x0021) / \
        IP(src=ip_addr, dst="1.1.1.1") / \
        ICMP()

    return packet


def sniff_int(interface, code, wait=2):
    """
    sniff interface
    :param interface: Client interface
    :param code: LCP code
    :param wait: how many sec wait answer packets (default 1 sec)
    :return: packet
    """

    response = sniff(iface=interface, timeout=wait, count=1)
    try:
        if response[0][Ether].type == 0x8864:
            print("    >>> LCP PACKET code {0}".format(response[0][PPP_LCP].code))
            if response[0][PPP_LCP].code == code:
                return response[0]
    except IndexError:
        return None

def sniff_all_pppoe(interface, count, wait=10):
    """
    sniff interface
    :param interface: Client interface
    :param code: LCP code
    :param wait: how many sec wait answer packets (default 1 sec)
    :return: packet
    """
    pkts=[]
    response = sniff(iface=interface, timeout=wait, count=count)
    for resp in response:
        if resp[Ether].type == 0x8864:
            print("    >>> LCP PACKET code {0}".format(resp[PPP_LCP].code))
            pkts.append(resp)
        if resp[Ether].type == 0x8863:
            print("    >>> PPPoE Packet code {0}".format(resp.code))
            pkts.append(resp)
    return pkts


def establish_ipcp_connect(iface, id, src, dst, wait):
    """
    sniff interface
    :param interface: Client interface
    :param id: session ID
    :param src: src mac
    :param dst: dst mac
    """

    #Отправляем IPCP configure request и ждем Nack
    configure_req=create_packet_ipcp_config(dst, id, 1, 1, "0.0.0.0")
    response=send_and_recv(iface, configure_req, wait)
    configure_nak = find_packet_ppp_ipcp(response, 0x3)
    if(configure_nak == None):
        return False

    #Запрашиваем IP, который предложил сервер
    ip=configure_nak[PPP_IPCP_Option_IPAddress].data
    configure_req2=create_packet_ipcp_config_pkt(configure_nak,1,id)
    response=send_and_recv(iface, configure_req2, wait)
    configure_aсk = find_packet_ppp_ipcp(response, 0x2)
    if(configure_aсk == None):
        return False
    
    #Отвечаем ACK'ом на реквест сервера
    server_conf_req=find_packet_ppp_ipcp(response, 0x1)
    if(server_conf_req == None):
        return False
    conf_ack_toServer=create_packet_ipcp_config_pkt(server_conf_req,2,id)
    response=send_and_recv(iface, conf_ack_toServer, wait)

    print("IPCP established")

def establish_full_session_without_auth(iface, service, wait):
    """
    Establish full pppoe session without auth
    :param interface: Client interface
    :param service: Service in padi
    :param wait: how many sec wait on connect
    """

    pkt=establish_lcp_connect("ppp0", iface, service, wait)
    id=pkt[PPPoE].sessionid
    src=pkt[Ether].dst
    dst=pkt[Ether].src
    answer=establish_ipcp_connect(iface, id, src, dst, wait)

    return id,dst

def establish_full_session_with_PAP(iface, service, wait):
    """
    Establish full pppoe session with PAP (admin:admin)
    :param interface: Client interface
    :param service: Service in padi
    :param wait: how many sec wait on connect
    """
    pads = establish_pppoe_session("ppp0", iface, service)
    if pads == None:
        return False

    dst = pads[Ether].src
    src = pads[Ether].dst
    sessionid = pads[PPPoED].sessionid

    # send configure-request
    config_request = create_packet_lcp_config(dst, sessionid, 0x01, 1, 1492, 1)
    print(" -> LCP Configure-Request")
    packets = send_and_recv(iface, config_request)

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
    packets = send_and_recv(iface, configuration_reject)

    # get configure-request
    print(" <- {0} packet(s)".format(len(packets)))
    configure_req = find_packet_ppp_lcp(packets, 0x01)
    if configure_req is None:
        return False

    # send configure-ack
    config_ack = create_packet_lcp_config_pkt(configure_req, 0x02)
    print(" -> LCP Congigure-Ack")
    sendp(config_ack, iface=iface)

    # send authenticate request
    ## \x61\x64\x6d\x69\x6e: admin
    auth_request = create_packet_pap(dst, sessionid, '\x61\x64\x6d\x69\x6e', '\x61\x64\x6d\x69\x6e')
    print(" -> PAP Authenticate-Request")
    packets = send_and_recv(iface, auth_request, wait=0.2)

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

    answer=establish_ipcp_connect(iface, sessionid, src, dst, wait)
    print('Session with PAP established')
    return True





