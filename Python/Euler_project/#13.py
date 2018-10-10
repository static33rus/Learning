p= open('/home/m_pavlov/some.txt', "r")
k=0
for line in p:
    s=line
    a=int(s)
    k=k+a
p.close()
s=str(k)
print s[1:10]
