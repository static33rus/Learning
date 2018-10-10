p= open('/home/m_pavlov/some.txt', "r")
k=0
for line in p:
    s=line
    for i in range (0,1000):
        if s[i+3]=='\n':
            break 
        else:
            a=int(s[i])
            b=int(s[i+1])
            c=int(s[i+2])
            d=int(s[i+3])
            if a*b*c*d > k:
                k=a*b*c*d
                print ("%ix%ix%ix%d=%i \n" % (a,b,c,d,k))
p.close()
