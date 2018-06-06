day, month, year = ARGV
month_list=[" ","января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"]
#Определяем номер месяца
month_number=month_list.index(month)
t1=Time.mktime(year,month_number,day)
t2=Time.mktime(year.to_i+1,1,1)
t3=(t2-t1)/60/60/24-1
puts t3.round(0)
