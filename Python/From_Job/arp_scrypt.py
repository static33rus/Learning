 f = open('hernya.txt',"w")
 for i in range (0,1):
     for j in range (0,40):
          for k in range (0,256):
             f.write ( "arp 10.%s.%s.%s %04x.%04x.%04x \n" % (i,j,k,i,j,k))
 f.close()

