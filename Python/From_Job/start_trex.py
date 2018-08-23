#!/usr/bin/python3.5
import subprocess
import sys
import time
import json
import os;

path = sys.path.append(os.environ['TREX_PATH'])
from trex_stl_lib.api import *
from scapy.all import *
import ipaddress
import math
from termcolor import colored
from optparse import OptionParser

def createStream(dst_mac,
                 dst: str,
                 id:str,
                 src: str,
                 speed: int,
                 size: int) -> STLStream:
    pkt = Ether(dst=dst_mac, src=RandMAC())/PPPoE(sessionid=id)/PPP(proto=33)/IP(src=src, dst=dst)/UDP(dport=12, sport=1025)
    pad = max(0, size - len(pkt)) * 'x'
    return STLStream(packet=STLPktBuilder(pkt=pkt / pad),mode=STLTXCont(bps_L2=speed))



if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option(
        "-b", "--bandiwth", dest="link_speed", default=1000, help="Total Bandwidth in mbps, which will separate for each subscriber"
    )
    parser.add_option(
        "-m", "--dstmac", dest="dst_mac", default='1c:87:76:40:af:7a', help="Destination mac for packets, by default is 1c:87:76:40:af:7a"
    )
    parser.add_option(
        "-c", "--count", dest="user_count", default=1000, help="Subscriber's count"
    )
    parser.add_option(
        "-i", "--iface", dest="users_iface", default='eth19', help="Interface for generating traffic from subscribers"
    )
    parser.add_option(
        "-n", "--network", dest="users_network", default='1.1.0.0/16', help="Network for subscribers, default is 1.1.0.0/16"
    )
    parser.add_option(
        "-s", "--size", dest="pkt_size", default=512, help="Packet size, default is 512"
    )
    parser.add_option(
        "-d", "--duration", dest="duration", default=30, help="Duration in seconds. Default is 30"
    )
    parser.add_option(
        "-p", "--path", dest="path", default='/etc/freeradius/', help="path to radius server, default is /etc/freeradius/"
    )
    parser.add_option(
        "-l", "--loss", dest="loss", default=0.5, help="Percent of packet drops at which test in considered successful"
    )
    (options, args) = parser.parse_args()
    k=1000000 #1mb
    link_speed=int(options.link_speed)*k 
    dst_mac=options.dst_mac
    user_count=int(options.user_count)
    users_iface=options.users_iface
    users_network=options.users_network
    pkt_size=int(options.pkt_size)
    duration=int(options.duration)
    radius_path=options.path
    loss=int(options.loss)

    trex_client = STLClient(username="trex", server="127.0.0.1", sync_port=4701, async_port=4700)
    
    try:
        streams=[]
        subprocess.run([radius_path+'radius_config_users.py', '-c', str(user_count), '-n', users_network])
        subprocess.run(['mv', 'users', radius_path])
        subprocess.run(['freeradius'])
        time.sleep(2)
        print('Поднимаем {} сессий...'.format(user_count))
        subprocess.run(['./pppoe_multi_perf_last.py','-i',users_iface, '-c', str(user_count), '-r', 'False'])
        subprocess.run(['chmod','666','packet_info.json'])
        f=open('packet_info.json')
        tmp=f.read()
        f.close()
        if tmp.endswith('{}'):
            print("Придется подредактировать")
            f=open('packet_info.json','w')
            f.write(tmp[:-2])
            f.close()
        print('Стартуем t-rex сервер...')
        subprocess.run(['screen', '-m', '-d', '-S', 'server', './t-rex-64', '-i', '--cfg', '/etc/cfg_trex_pppoe', '--software'])
        time.sleep(10)
        print('Подключаемся к t-rex серверу...')
        trex_client.connect()
        trex_client.reset(ports=[0,1])

        with open('packet_info.json') as f:
            data = json.load(f) 

        for element in data:
            id=int("0x"+data[element],16)        
            streams.append(createStream(dst_mac=dst_mac, dst="192.168.1.2",src=element,id=id, speed=link_speed/len(data), size=pkt_size))
        trex_client.add_streams(streams, ports=1)



#####start capture ########
#        trex_client.set_service_mode(ports=0)
#        capture = trex_client.start_capture(rx_ports=0, limit=10000)    
######################

        trex_client.start(ports=[1], duration=duration, force=True)
        while duration > 0:
            try:
                time.sleep(2)
                duration -= 2
               # print(str(duration), sep=' ', end=' ', flush=True)
                results = trex_client.get_stats()
                print('Total tx bps L1 port {port} = {speed}'.format(port=1, speed=format(results[1]['tx_bps_L1'] / k, '.3f')))
                print('Total rx bps L1 port {port} = {speed}'.format(port=0, speed=format(results[0]['rx_bps_L1'] / k, '.3f')))
                print('---------------------')
            except KeyboardInterrupt:
                trex_client.stop(ports=[1])
                break
        print(colored('Total output pkts: {}'.format(results[1]['opackets']),'blue'))
        print(colored('Total input pkts: {}'.format(results[0]['ipackets']),'blue'))
        drops=results[1]['opackets']-results[0]['ipackets']
        drop_percent=drops/results[1]['opackets']*100
        if drop_percent < loss:
            print(colored('Packet drops: {}'.format(drops),'green'))
            print(colored('Drops percent: {:.2f}'.format(drop_percent),'green'))
            print(colored('SUCCESS','green'))
        else:
            print(colored('Packet drops: {}'.format(drops),'red'))
            print(colored('Drops percent: {:.2f}'.format(drop_percent),'red'))
            print(colored('FAIL, reason: too much packet loss','red'))
       # trex_client.wait_on_traffic(ports=[0,1])
    
#####stop capture ########
#        trex_client.stop_capture(capture['id'], 'tx.pcap')
#        trex_client.set_service_mode(ports=0, enabled=False)
#        trex_client.reset(ports=0)
######################
    except KeyboardInterrupt:
        trex_client.disconnect()
    finally:
#        print(results)
        print('Завершаем работу t-rex сервера, радиуса, возвращаем порты из dpdk')
        trex_client.disconnect()
        subprocess.run(['screen', '-X', '-S', 'server', 'quit'])
        subprocess.run(['./dpdk_nic_bind.py', '-b', 'ixgbe', '0000:88:00.0', '0000:88:00.1'])
#        subprocess.run(['./dpdk_nic_bind.py', '--status'])
        subprocess.run(['sudo', 'ifconfig', 'eth19', 'up'])
        subprocess.run(['pkill','-9','freeradius'])












