#!/usr/bin/python3
import pexpect
import sys


def ciscoInterfaces():
    global nagibator, port
    for i in range(25):
        try:
            cisco = pexpect.spawn('telnet {ip} {port}'.format(ip=nagibator, port=port+i), logfile=sys.stdout.buffer)
            cisco.sendline('\r')
            cisco.expect('R.*#')
            cisco.sendline('conf t\r')
            cisco.expect('config')
            cisco.sendline('interface gig0/0\r')
            cisco.expect('config-if')
            cisco.sendline('no shut\r'
                           'ip address 192.168.2.{address} 255.255.255.0\r'
                           'ip router isis 1\r'
                           'mpls ip\r'
                           'exit\r'.format(address=i+1))
            cisco.expect('config')
            cisco.sendline('interface loopback 0\r'
                           'ip address {a}.{a}.{a}.{a} 255.255.255.255\r'
                           'ip router isis 1\r'
                           'end\r'.format(a=i+1))
            cisco.expect('#')
            cisco.sendline('wr\r')
            # cisco.expect('confirm')
            # cisco.sendline('\r')
            cisco.expect('R.*#')
        finally:
            cisco.send("\035")
            cisco.expect("telnet>")
            cisco.sendline("quit")
            cisco.expect(pexpect.EOF)


def ciscoVRF():
    global nagibator, port
    k=0
    for i in range(25):
        try:
            cisco = pexpect.spawn('telnet {ip} {port}'.format(ip=nagibator, port=port + i), logfile=sys.stdout.buffer)
            cisco.sendline('\r')
            cisco.expect('R.*#')
            cisco.sendline('conf t\r')
            cisco.expect('config')
            for j in range(25):
                cisco.sendline('ip vrf {a}\r'
                               'rd {a}:{a}\r'
                               'route-target export {a}:{a}\r'
                               'route-target export {a}:{a}\r'.format(a=k+j+1))
            cisco.sendline('end\r')
            cisco.expect('#')
            cisco.sendline('wr\r')
            # cisco.expect('confirm')
            # cisco.sendline('\r')
            cisco.expect('R.*#')
            k+=25
        finally:
            cisco.send("\035")
            cisco.expect("telnet>")
            cisco.sendline("quit")
            cisco.expect(pexpect.EOF)

def ciscoISIS():
    global nagibator, port
    for i in range(25):
        try:
            cisco = pexpect.spawn('telnet {ip} {port}'.format(ip=nagibator, port=port + i), logfile=sys.stdout.buffer)
            cisco.sendline('\r')
            cisco.expect('R.*#')
            cisco.sendline('conf t\r')
            cisco.expect('config')
            cisco.sendline('router isis 1\r'
                           'net 49.0001.0000.0000.{:04}.00\r'
                           'is-type level-2-only\r'.format(i+1))
            cisco.sendline('end\r')
            cisco.expect('#')
            cisco.sendline('wr\r')
            # cisco.expect('confirm')
            # cisco.sendline('\r')
            cisco.expect('R.*#')
        finally:
            cisco.send("\035")
            cisco.expect("telnet>")
            cisco.sendline("quit")
            cisco.expect(pexpect.EOF)

def ciscoBGP():
    global nagibator, port
    for i in range(25):
        try:
            cisco = pexpect.spawn('telnet {ip} {port}'.format(ip=nagibator, port=port + i), logfile=sys.stdout.buffer)
            cisco.sendline('\r')
            cisco.expect('R.*#')
            cisco.sendline('conf t\r')
            cisco.expect('config')
            cisco.sendline('router bgp 100\r'
                           'neighbor 100.100.100.100 remote-as 100\r'
                           'neighbor 100.100.100.100 update-source Loopback0\r'
                           'address-family vpnv4\r'
                           'neighbor 100.100.100.100 activate\r')
            cisco.sendline('end\r')
            cisco.expect('#')
            cisco.sendline('wr\r')
            # cisco.expect('confirm')
            # cisco.sendline('\r')
            cisco.expect('R.*#')
        finally:
            cisco.send("\035")
            cisco.expect("telnet>")
            cisco.sendline("quit")
            cisco.expect(pexpect.EOF)


def ciscoSave():
    global nagibator, port
    for i in range(25):
        try:
            cisco = pexpect.spawn('telnet {ip} {port}'.format(ip=nagibator, port=port + i), logfile=sys.stdout.buffer)
            cisco.sendline('end\r')
            cisco.expect('R.*#')
            cisco.sendline('wr\r')
            cisco.expect('R.*#')
        finally:
            cisco.send("\035")
            cisco.expect("telnet>")
            cisco.sendline("quit")
            cisco.expect(pexpect.EOF)


if __name__ == '__main__':
    nagibator = '192.168.251.2'
    port = 5003
    ciscoInterfaces()
    ciscoVRF()
    ciscoISIS()
    ciscoBGP()
    ciscoSave()


