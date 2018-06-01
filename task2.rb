require 'unicode'
day, month, year = ARGV
month=Unicode::downcase(month)
def define_god(year)
#Функция определения високосного года, возвращает true если високосный
    if (year%4==0 and year%100!=0) or (year%400==0)
    return true
    else
    return false
    end
end
visokosniy_god=define_god(year.to_i)  
 
month_list=[" ","января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"]
days_list=[" ",31,28,31,30,31,30,31,31,30,31,30,31]
#Определяем номер месяца
month_number=month_list.index(month)
sum=0
# Считаем кол-во дней до НГ, но не учитываем текущий день в месяце
for x in (month_number)..12 do
    sum=sum+days_list[x]
end

#Считаем кол-во дней до нг с учетом дня в месяце и високосного года
if (visokosniy_god)
days_list[2]=29
if (day.to_i<=29 and month_number<=2 and day.to_i<=days_list[month_number])
noviy_god_cherez=sum-day.to_i+1
elsif (month_number>2 and day.to_i<=days_list[month_number])
noviy_god_cherez=sum-day.to_i
end
elsif day.to_i<=days_list[month_number]
noviy_god_cherez=sum-day.to_i
end
puts noviy_god_cherez+1
