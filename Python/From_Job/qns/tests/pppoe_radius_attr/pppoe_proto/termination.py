#!/usr/bin/python3
import time
from .packet import *

import logging

from .configure import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

def run_term_00(test,interface):  
##Устанавливаем сессию, потом ее клирим с роутера и проверяем то, что отсылается term request и PADT
    qns_call('\nqns say "enable" --expect "ecorouter#"')
    qns_call('\nqns say "conf t" --expect "ecorouter(config)#"')
    qns_call('\nqns say "pppoe-profile 0" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "ppp max-echo 0" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "ppp max-terminate 1" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "ppp timeout-retry 1" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "no ppp authentication" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "end" --expect "ecorouter#"')

    qns_call('\nqns say "enable" --expect "ecorouter#"')
    qns_call('\nqns say "clear subscribers bmi.0 all" --expect "ecorouter#"')
    time.sleep(2)

    establish_full_session_without_auth("veth0", 'ololo', 0.1)
    time.sleep(1)

    qns_call('\nqns say "enable" --expect "ecorouter#"')
    qns_call('\nqns say "conf t" --expect "ecorouter(config)#"')
    qns_call('\nqns say "pppoe-profile 0" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "ppp max-echo 0" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "ppp max-terminate 2" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "ppp timeout-retry 1" --expect "ecorouter(config-pppoe)#"')
    qns_call('\nqns say "end" --expect "ecorouter#"')

    qns_call('\nqns say "enable" --expect "ecorouter#"')
    qns_call('\nqns say "clear subscribers bmi.0 all" --expect "ecorouter#"')
    sniffed=sniff_all_pppoe("veth0", 4, 3)

    n=0
    k=0
    for pkt in sniffed:
    	if pkt[Ether].type == 0x8864 and pkt[PPP_LCP].code == 5:
    		print("Client recieved LCP Term request")
    		n=n+1
    	if pkt[Ether].type == 0x8863 and pkt.code == 0xa7:
    		print("Client recieved PADT")
    		k=k+1

    if n!=0 and k!=0:
    	return True

def run_term_01(test,interface):
##Устанавливаем сессию, потом закрываем ее с клиента, смотрим, что приходит term req и ack с роутера, проверяем на роутере в CLI, что сессия закрылась и роутер не завис
    id,dst=establish_full_session_without_auth("veth0", 'ololo', 0.1)
    print("Send termination request to server")
    term_request = create_packet_lcp_without_options(dst, id, 0x05, 0x01, 4)
    packets = send_and_recv("veth0", term_request)
    n=0
    k=0
    for pkt in packets:
        if pkt[Ether].type == 0x8864 and pkt[PPP_LCP].code == 5:
            print("Client recieved LCP Term request")
            n=n+1
        if pkt[Ether].type == 0x8864 and pkt[PPP_LCP].code == 6:
            print("Client recieved LCP ACK")
            k=k+1

    qns_call('\nqns say "show subscribers bmi.0" --expect "Total subscribers: 0"')
    if n!=0 and k!=0:
        return True


def register(testdict):
    testdict.update({'term_00': run_term_00})
    testdict.update({'term_01': run_term_01})
