 f = open('hernya.txt',"w")
 for i in range (0,1):
     for j in range (0,99):
          f.write ( "pkt%s=Ether(src='aa:aa:aa:aa:a%s:%02x', dst='bb:bb:bb:bb:b%s:%02x')/IP(src='1.1.%s.%s', dst='192.168.1.1')/ICMP()   \n" % (j,i,j,i,j,i,j))
          f.write ( "sendp(pkt%s*1, iface='tap0')  \n" % (j))
 f.close()



