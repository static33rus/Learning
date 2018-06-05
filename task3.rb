t1, t2 = ARGV
t1=Integer(t1)
t2=Integer(t2)
sum=t1+t2
#Создадим функцию, которая будет возвращать целое от деления и остаток. С помощью нее будем переводить сек в минуты, минуты в часы, часы в дни и тд
def get_norm_date(number, k)
    ostatok=number%k
    celoe=(number-ostatok)/k
    return ostatok, celoe
end
# С помощью функции переведем в часы, минуты и секунды. Можно и в часы, но я закомментил, так как в задании это не требуется
sec, min = get_norm_date(sum,60)
min, hours = get_norm_date(min,60)
seconds_list=['секунд','секунда','секунды','секунды','секунды','секунд','секунд','секунд','секунд','секунд']
minutes_list=['','минута','минуты','минуты','минуты','минут','минут','минут','минут','минут']
hours_list=['','час','часа','часа','часа','часов','часов','часов','часов','часов']

lsec=Integer(sec.to_s[-1])
lmin=Integer(min.to_s[-1])
lh=Integer(hours.to_s[-1])

if sec.to_s[0]=='1' and sec.to_s.length==2 
seconds_list[lsec]='секунд'
end
if min.to_s[0]=='1' and min.to_s.length==2 
minutes_list[lmin]='минут'
end
if hours.to_s[0]=='1' and hours.to_s.length==2 
hours_list[lh]='часов'
end


if hours==0 and min==0 and sec==0
puts '0 секунд'
elsif hours==0 and min==0 and sec!=0
puts "#{sec.to_s} #{seconds_list[lsec]}"
elsif hours==0 and min!=0 and sec==0
puts "#{min.to_s} #{minutes_list[lmin]}"
elsif hours==0 and min!=0 and sec!=0
puts "#{min.to_s} #{minutes_list[lmin]} #{sec.to_s} #{seconds_list[lsec]}"
elsif hours!=0 and min==0 and sec==0
puts "#{hours.to_s} #{hours_list[lh]}"
elsif hours!=0 and min==0 and sec!=0
puts "#{hours.to_s} #{hours_list[lh]} #{sec.to_s} #{seconds_list[lsec]}"
elsif hours!=0 and min!=0 and sec==0
puts "#{hours.to_s} #{hours_list[lh]} #{min.to_s} #{minutes_list[lmin]}"
elsif hours!=0 and min!=0 and sec!=0
puts "#{hours.to_s} #{hours_list[lh]} #{min.to_s} #{minutes_list[lmin]} #{sec.to_s} #{seconds_list[lsec]}"
end



