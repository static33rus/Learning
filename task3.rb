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
#hours, days = get_norm_date(hours,24)
puts "#{hours.to_s} час #{min.to_s} минут #{sec.to_s} секунд"

