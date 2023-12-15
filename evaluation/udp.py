from socket import *
import struct
#'192.168.100.228'
#localip = '192.168.10.199'
localip = '192.168.100.228'
f = open('./data/prediction.txt', mode='a+')
sock = socket()
sock.bind((localip, 8888))
sock.listen(1)
with sock:
    client, addr = sock.accept()
    with client, client.makefile() as clientfile:
        while True:
            head = clientfile.read(4)
            if not head:
                break
            h = struct.unpack('>ccH', head.encode())
            datalen = int(h[2])
            data = clientfile.read(datalen)
            f.write(data + '\n')
f.close()
