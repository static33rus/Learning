#!/usr/bin/python3
import pexpect
import sys
import time
import ipaddress

def RDPInterfaces(start,stop):
    global ecorouter, port
    ipv4 = ipaddress.ip_address('10.10.0.1')
    rdp = pexpect.spawnu('telnet {ip}'.format(ip=ecorouter))
    time.sleep(2)
    rdp.logfile = sys.stdout
    rdp.expect(":")
    time.sleep(2)
    rdp.send("admin" + "\r")
    rdp.expect(":")
    rdp.send("admin" + "\r")
    rdp.send("\r\n")
    time.sleep(2)
    rdp.expect(">")
    rdp.sendline('en\r')
    rdp.expect('#')
    rdp.sendline('conf t\r')
    rdp.expect('config')
    try:
        for i in range(start,stop):
            ipv4=ipv4+256
            rdp.sendline('interface {name}\r'.format(name=i+1))
            rdp.expect('#')
            rdp.sendline('ip vrf forwarding {vrf}\r'
                         'ip address {address} 255.255.255.0\r'.format(address=str(ipv4), vrf=i+1))
            rdp.expect('config')
            rdp.sendline('port te0/1\r'
                           'service-instance {num}\r'
                           'encapsulation dot1q {num} exact\r'
                           'rewrite pop 1\r'
                           'connect ip interface {num}\r'.format(num=i+1))
            rdp.expect('#')
    finally:
        rdp.send("\035")
        rdp.expect("telnet>")
        rdp.sendline("quit")
        rdp.expect(pexpect.EOF)

def RDPvrf(start,stop):
    global ecorouter, port
    rdp = pexpect.spawnu('telnet {ip}'.format(ip=ecorouter))
    time.sleep(2)
    rdp.logfile = sys.stdout
    rdp.expect(":")
    time.sleep(2)
    rdp.send("admin" + "\r")
    rdp.expect(":")
    rdp.send("admin" + "\r")
    rdp.send("\r\n")
    time.sleep(2)
    rdp.expect(">")
    rdp.sendline('en\r')
    rdp.expect('#')
    rdp.sendline('conf t\r')
    rdp.expect('config')
    for i in range(start,stop):
        rdp.sendline('ip vrf {name}\r'.format(name=i+1))
        rdp.expect_exact('ecorouter(config-vrf)#')
        rdp.sendline('rd {n}:{n}\r'
                       'route-target both {n}:{n}\r'
                       'exit\r'.format(n=i+1))
        rdp.expect_exact('ecorouter(config-vrf)#')
    time.sleep(30)
    rdp.send("\035")
    rdp.expect("telnet>")
    rdp.sendline("quit")
    rdp.expect(pexpect.EOF)


def RDPbgp(start,stop):
    global ecorouter, port
    rdp = pexpect.spawnu('telnet {ip}'.format(ip=ecorouter))
    time.sleep(2)
    rdp.logfile = sys.stdout
    rdp.expect(":")
    time.sleep(2)
    rdp.send("admin" + "\r")
    rdp.expect(":")
    rdp.send("admin" + "\r")
    rdp.send("\r\n")
    time.sleep(2)
    rdp.expect(">")
    rdp.sendline('en\r')
    rdp.expect('#')
    rdp.sendline('conf t\r')
    rdp.expect('config')
    rdp.sendline('router bgp 100\r')
    rdp.expect('#')
    try:
        for i in range(25):
            rdp.sendline('neighbor {n}.{n}.{n}.{n} remote-as 100\r'
                         'neighbor {n}.{n}.{n}.{n} update-source 100.100.100.100\r'
                         'address-family vpnv4 unicast\r'
                         'neighbor {n}.{n}.{n}.{n} activate\r'
                         'exit\r'.format(n=i+1))
            rdp.expect('#')
        for j in range(start,stop):
            rdp.sendline('address-family ipv4 vrf {n}\r'
                         'redistribute connected\r'
                         'exit\r'.format(n=j+1))
            rdp.expect('#')
    finally:
        rdp.send("\035")
        rdp.expect("telnet>")
        rdp.sendline("quit")
        rdp.expect(pexpect.EOF)

if __name__ == '__main__':
    ecorouter = '192.168.251.9'
    RDPvrf(0,200)
    RDPvrf(199,400)
    RDPvrf(399,625)
    RDPInterfaces(0,200)
    time.sleep(30)
    RDPInterfaces(199,400)
    time.sleep(30)
    RDPInterfaces(399,625)
    time.sleep(30)
    RDPbgp(0,200)
    time.sleep(30)
    RDPbgp(199,400)
    time.sleep(30)
    RDPbgp(399,625)



