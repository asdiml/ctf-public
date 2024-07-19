toconvert = 'gcedi'
lilendian = ''.join([hex(ord(toconvert[len(toconvert)-i-1]))[2:] for i in range(len(toconvert))])
bigendian = ''.join([lilendian[len(lilendian)-i*2-2:len(lilendian)-i*2] for i in range(int(len(lilendian)/2))])
print('Little endian representation: ' + lilendian)
print('Big endian representation: ' + bigendian)