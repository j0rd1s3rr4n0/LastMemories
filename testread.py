filepath="Iliad.txt"
with open(filepath) as fp:
   line = fp.readline()
   cnt = 1
   while line:
       print("{}".format(line.strip()))
       line = fp.readline()
       line = line*1000
       print(line)
       cnt += 1