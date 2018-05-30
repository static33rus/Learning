i,a,b = ARGV
def translate_to_sys10(num,osnova)
    alph = ("a".."z").to_a
    chars=num.split('')
    sys10=0
    len=num.length()-1
    for x in chars do
        if (alph.find_index(x.downcase)!=nil and alph.find_index(x.downcase)+10>=osnova.to_i)
        return "Нет такой буквы в этой системе"
        end
        if alph.find_index(x.downcase)==nil
        sys10=x.to_i*osnova.to_i**len+sys10
        len=len-1
        else
        sys10=(alph.find_index(x.downcase)+10)*osnova.to_i**len+sys10
        len=len-1
        end
    end
    return sys10
end

def celoe_i_ostatok(num,del)
    ostatok=num%del
    celoe=num/del
    return celoe,ostatok
end

def translate_sys10_toAnotherSys(num,sys)
    alph = ("a".."z").to_a
    list=[]
    if num<sys
        return num
    else
        while num>=sys do
            num,ostatok=celoe_i_ostatok(num,sys)
            if ostatok>=10
                ostatok=alph[ostatok-10]
            end  
            list.insert(0,ostatok)
        end
        if num>=10
            num=alph[num-10]
        end           
        list.insert(0,num)
        num=list.join
        return num
    end
end

new_sys=translate_sys10_toAnotherSys(i.to_i,a.to_i)
#sys10=translate_to_sys10(i,a)
puts new_sys
        

