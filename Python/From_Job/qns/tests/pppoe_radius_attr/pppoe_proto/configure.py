#!/usr/bin/python3
import os
import sys

def qns_call(cmd):
    a=os.system(cmd)
    if a!=0:
        raise Exception('Error in configuration!')

def configure_radius(node,ip,secret='12121212'):
    client=ip[0:(len(ip)-1)]+'0'
    qns_call("\nqns node-ip {} {}/24".format(node,ip))
    qns_call("\nqns container-exec {node} sh -c '"
              "cd /etc/raddb/;"
              "rm users;"
              "rm clients.conf;"
              "echo \"client {client}/24 {{\" > clients.conf;"
              "echo \"        secret          = {secret}\" >> clients.conf;"
              "echo \"}}\" >> clients.conf;"
              "echo \"admin    Cleartext-Password := 'admin'\" > /etc/raddb/mods-config/files/authorize;"
              "echo \"        Idle-Timeout = 2,\" >> /etc/raddb/mods-config/files/authorize;"
              "echo \"        Session-Timeout = 3\" >> /etc/raddb/mods-config/files/authorize;"
              "echo \"VENDOR        RDP        45555\" > /etc/raddb/dictionary;"
              "echo \"BEGIN-VENDOR RDP\" >> /etc/raddb/dictionary;"
              "echo \"ATTRIBUTE    SERVICE_NAME        250    string\" >> /etc/raddb/dictionary;"
              "echo \"END-VENDOR    RDP\" >> /etc/raddb/dictionary;'".format(node=node, client=client, secret=secret))
    qns_call("\nqns container-exec {node} echo /etc/raddb/clients.conf".format(node=node))
    qns_call("\nqns container-exec {node} cat /etc/raddb/clients.conf".format(node=node))
    qns_call("\nqns container-exec {node} echo /etc/raddb/mods-config/files/authorize".format(node=node))
    qns_call("\nqns container-exec {node} cat /etc/raddb/mods-config/files/authorize".format(node=node))
    qns_call("\nqns container-exec {node} echo /etc/raddb/dictionary".format(node=node))
    qns_call("\nqns container-exec {node} cat /etc/raddb/dictionary".format(node=node))

def configure_radius_group(name,server,secret='12121212'):
    qns_call('\nqns say "conf t" --expect "ecorouter(config)#"')
    qns_call('\nqns say "radius-group {}" --expect "ecorouter(config-radius-group)#"'.format(name))
    qns_call('\nqns say "server {} secret {}" --expect "ecorouter(config-radius-group)#"'.format(server,secret))
    qns_call('\nqns say "end" --expect "ecorouter#"')

def configure_sub_aaa(name,radius,acct=None):
    qns_call('\nqns say "conf t" --expect "ecorouter(config)#"')
    qns_call('\nqns say "subscriber-aaa {}" --expect "ecorouter(config-sub-aaa)#"'.format(name))
    qns_call('\nqns say "authentication radius {}" --expect "ecorouter(config-sub-aaa)#"'.format(radius))
    if acct!=None:
        qns_call('\nqns say "accounting radius {}" --expect "ecorouter(config-sub-aaa)#"'.format(radius))
    qns_call('\nqns say "end" --expect "ecorouter#"')

def configure_pppoe_profile(name,ac_name='EcoRouter',gateway='192.168.10.1',pool=None,pado_timeout=None,serv_name=None,auth=None,aaa=None,sub_service=None):
#auth значения: pap, chap, ms-chap, ms-chap-v2
    qns_call('\nqns say "conf t" --expect "ecorouter(config)#"')
    qns_call('\nqns say "pppoe-profile {}" --expect "ecorouter(config-pppoe)#"'.format(name))
    qns_call('\nqns say "tag-ac-name {}" --expect "ecorouter(config-pppoe)#"'.format(ac_name))
    qns_call('\nqns say "gateway ipv4 {}" --expect "ecorouter(config-pppoe)#"'.format(gateway))
    if pool!=None:
        qns_call('\nqns say "pool ipv4 {}" --expect "ecorouter(config-pppoe)#"'.format(pool))
    if pado_timeout!=None:
        qns_call('\nqns say "pado-timeout {}" --expect "ecorouter(config-pppoe)#"'.format(pado_timeout))
    if serv_name!=None:
        qns_call('\nqns say "tag-service-name {}" --expect "ecorouter(config-pppoe)#"'.format(serv_name))
    if auth!=None:
        qns_call('\nqns say "ppp authentication {}" --expect "ecorouter(config-pppoe)#"'.format(auth))
    if aaa!=None:
        qns_call('\nqns say "set aaa {}" --expect "ecorouter(config-pppoe)#"'.format(aaa))
    if sub_service!=None:
        qns_call('\nqns say "set service {}" --expect "ecorouter(config-pppoe)#"'.format(sub_service))
    qns_call('\nqns say "end" --expect "ecorouter#"')

def configure_port(port,si,iface,encaps='untagged'):
    qns_call('\nqns say "conf t" --expect "ecorouter(config)#"')
    qns_call('\nqns say "port {port}" --expect "ecorouter(config-port)#"'.format(port=port))
    qns_call('\nqns say "service-instance {si}" --expect "ecorouter(config-service-instance)#"'.format(si=si))
    qns_call('\nqns say "encapsulation {encaps}" --expect "ecorouter(config-service-instance)#"'.format(encaps=encaps))
    qns_call('\nqns say "connect ip interface {iface}" --expect "ecorouter(config-service-instance)#"'.format(iface=iface))
    qns_call('\nqns say "end" --expect "ecorouter#"')


         
