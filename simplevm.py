#!/usr/bin/python

f = open("./code", 'r')
data = f.read()
i = 0
idx = 2
flag_nums = [0x01, ]
while True:
    #print hex(ord(data[i]))
    if ord(data[i]) == 0x0:
        print "0x00    exit(0)"
        break
    if ord(data[i]) == 0x02:
        idx -= 1
        print "0x02    idx = idx - 1"
        i += 1
    if ord(data[i]) == 0x01:
        print "0x01",hex(ord(data[i+1])),hex(ord(data[i+2])),hex(ord(data[i+3])),hex(ord(data[i+4]))+"    Get V14."
        v14 = (ord(data[i+4])<<24) + (ord(data[i+3])<<16) + (ord(data[i+2])<<8) + ord(data[i+1])
        idx += 1
        print "flag_nums["+str(idx)+"] = ", v14
        i += 5
    if ord(data[i]) == 0x03:
        print "check_point["+str(ord(data[i+1]))+"]","+", "check_point["+str(ord(data[i+2]))+"]"
        i += 3
    if ord(data[i]) == 0x04:
        print "check_point["+str(ord(data[i+1]))+"]","-", "check_point["+str(ord(data[i+2]))+"]"
        i += 3
    if ord(data[i]) == 0x05:
        print "check_point["+str(ord(data[i+1]))+"]","=", "check_point["+str(ord(data[i+2]))+"]"
        i += 3
    if ord(data[i]) == 0x06:
        print "check_point["+str(ord(data[i+1]))+"]","=", "flag_nums["+str(ord(data[i+2]))+"]"
        i += 3
    if ord(data[i]) == 0x07:
        print "check_point["+str(ord(data[i+1]))+"]","^", "check_point["+str(ord(data[i+2]))+"]"
        i += 3
    if ord(data[i]) == 0x08:
        print "check_point["+str(ord(data[i+1]))+"]","|", "check_point["+str(ord(data[i+2]))+"]"
        i += 3
f.close()
        
    