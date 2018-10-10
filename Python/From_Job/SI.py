 f = open('hernya.txt',"w")
 for i in range (1,4001):
             f.write ( "service-instance %s \n" % (i))
             f.write ( "encapsulation dot1q %s exact \n" % (i))
             f.write ( "rewrite pop 1 \n" )
 f.write ( "exit \n" )
 f.write ( "exit \n" )
 for j in range (1,4001):
             f.write ( "int %s \n" % (j))
             f.write ( "connect port ge2 service-instance %s \n" % (j))
 f.close()
