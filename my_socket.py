import socket
import select
from multiprocessing import Process
from multiprocessing import Queue
import logging

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s %(filename)sline:%(lineno)d] <%(levelname)s> %(message)s',
                    datefmt='%Y %H:%M:%S')

# logging.basicConfig(level=logging.INFO, format='[%(filename)s line:%(lineno)d] <%(levelname)s> %(message)s',
#                     format='[%(asctime)s %(filename)sline:%(lineno)d] <%(levelname)s> %(message)s',
#                     datefmt='%a, %d %b %Y %H:%M:%S')


GLO_SOCK_CONN_BUFSIZE = 1024
GLO_SIGNAL_QUEUE = Queue()


DEBUG = logging.debug
INFO = logging.info


class SocketConn(object):
    def __init__(self, sock_conn, addr):
        self.conn = sock_conn
        self.addr = addr

        print "Connect setup", self.addr, sock_conn
        self.p = Process(target=self.receive_and_distribute)

    def __del__(self):
        if self.is_alive:
            self.stop()

    def receive_and_distribute(self):
        while True:
            data = self.conn.recv(GLO_SOCK_CONN_BUFSIZE)
            if not data:
                INFO("Connection from %s end", self.addr)
                self.conn.close()
                break
            # self.send_signal(data)
            print "Receive from client", data

    @property
    def is_alive(self):
        return self.p.is_alive()

    @property
    def pid(self):
        return self.p.pid

    @property
    def name(self):
        return self.p.name

    def start(self):
        # self.p.start()
        # self.p.join()
        self.receive_and_distribute()

    def stop(self):
        self.p.terminate()

    def send_signal(self, sig):
        GLO_SIGNAL_QUEUE.put(sig)


class MyServer(object):
    def __init__(self, host, port, buf_size=8092):
        server = socket.socket(socket.AF_INET, socket.SOCK_RAW )
        server.bind((host, port))
        server.listen(5)
        INFO("Socket listen at %s:%s .." % (host, port))
        self.server = server
        self.buf_size = buf_size

    def __del__(self):
        self.server.close()

    def waiting_for_connect(self):

        while True:
            try:
                readable, writeable, exception = select.select([self.server], [], [])
            except select.error, e:
                raise Exception(e)

            for sock in readable:
                if sock == self.server:
                    conn, addr = self.server.accept()
                    sock_conn = SocketConn(conn, addr)
                    sock_conn.start()
                    # Here we support one connection simply
                    break
                else:
                    raise Exception("We only wait for connection here")
            # Here we exit after one connection setup
            break
        self.server.close()


if __name__ == '__main__':
    my_server = MyServer("10.140.190.231", 33334)
    my_server.waiting_for_connect()
