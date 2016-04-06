import sys
import socket
import struct


if __name__ == '__main__':
    host = ('10.140.190.231', 33333)
    try:
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_obj.bind(host)
        socket_obj.listen(100)
    except socket.error, error_info:
        print 'can not start server', host
        sys.exit()
    print 'setup server successfully, and wait for client connection'

    while True:
        client_socket = socket_obj.accept()
        if client_socket:
            print 'one client has connected to server', client_socket[1]
            break
            
    next_crc_idx = 0
    start_flg = 1
    try_count = 0
    packet_cnt = 0
    bond_string = struct.pack('!I', 0x45454545)
    while True:
        packet = client_socket[0].recv(65565)
        if packet:
            msg_list = packet.split(bond_string)
            msg_list = [bond_string + each for each in msg_list if len(each)]
            for msg in msg_list:
                unpacked = struct.unpack('B'*len(msg), msg)
                packet_cnt += 1
                if len(unpacked) < 10:
                    print len(msg)
                    continue

                if start_flg or unpacked[9] != next_crc_idx:
                    start_flg = 0
                    if try_count <= 4:
                        try_count += 1
                        continue
                    print unpacked[9], next_crc_idx, packet_cnt
                next_crc_idx = (unpacked[9] + 1)%(2**32)
                try_count = 0