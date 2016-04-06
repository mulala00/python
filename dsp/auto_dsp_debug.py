import os
import re
import struct
import dirt_def
from termination import Handler as TermHandler

BYTE_ENDIAN = ">"


BB_DIR = "logs"


class EcdaParser(object):
    def __init__(self, ecda_file):
        with open(ecda_file, "r") as f:
            self._lines = f.readlines()

        with open(ecda_file, "r") as f:
            self._all = f.read()

    def find_signal(self, sig_no, sender=None, addr=None, owner=None, pool=None, size=None):
        if sig_no:
            sig_no = "%d" % sig_no
        else:
            sig_no = "\d+"

        if sender:
            sender = "%08x" % sender
        else:
            sender = "\w{8}"

        if addr:
            addr = "%08x" % addr
        else:
            addr = "\w{8}"

        if owner:
            owner = "%08x" % owner
        else:
            owner = "\w{8}"

        if pool:
            pool = "%d" % pool
        else:
            pool = "\d+"

        if size:
            size = "%d" % size
        else:
            size = "\d+"

        end_mask = "-------------------------------------------------------------------------------"

        re_s = "(%s) (%s) (%s) (%s)\s+(%s)\s+(%s)\s+\d+(.*?)%s" % (sig_no, sender, addr, owner, pool, size, end_mask)
        re_p = re.compile(re_s, re.DOTALL)
        m = re.findall(re_p, self._all)
        return m

    def find_process_sig(self, pid, sig_no):
        pass

    def find_singal_by_address(self, address):
        sig_found = False
        sig = ''

        for i in range(len(self._lines)):
            #  818958  00 81 6e 10 00 81 3f e0 00 6f 23 ed 00 00 03 e8
            if re.match('^%8x' % address + '  ', self._lines[i]) != None:
                sig += self._pack_signal_payload(self._lines[i].split()[1:])
                sig_found = True
                address += 16
            elif sig_found:
                break

        return sig

    def _pack_signal_payload(self, payload):
        packed = ''
        for i in range(len(payload)):
            packed += struct.pack('B', int(payload[i], 16))
        return packed

    def find_process_id(self, p_name):
        re_p = re.compile("(\w{8})  (%s)\s+\w+\s+\d+" % p_name, re.M)
        m = re.search(re_p, self._all)
        if m:
            return int(m.groups()[0], 16)
        else:
            raise Exception("process %s not found" % p_name)

    def pack_signal_data(self, data):
        """
        :param data:
        Hex Addr  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        --------  -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
        e2c45508  e2 bf 52 38 40 00 00 00 00 00 00 00 00 00 ff 00
        e2c45518  00 00 00 00 00 00 98 0c 8b e5 c4 67 d0 7c 9a 97
        e2c45528  f3 da ac b0 c8 dc ef ce bb a5 aa 44 e1 a4 ff f0

        :return:
        """
        payload = data.split("--------  -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --")[1]
        m = re.findall("( \w{2})", payload, re.M)
        m = map(lambda x: int(x, 16), m)

        sig_address = payload.split()[0]
        return int(sig_address, 16), struct.pack("%dB" % len(m), *m)


def get_dirt_data(ecda_obj):
    pid = ecda_obj.find_process_id("dirt")
    signals = ecda_obj.find_signal(sig_no=None, sender=pid, addr=pid, owner=pid, pool=None, size=1308)

    assert len(signals) == 1

    sig_no, sender, addr, owner, pool, size, data = signals[0]
    print sig_no, sender, addr, owner, pool, size, len(data)
    sig_add, sig_bin = ecda_obj.pack_signal_data(data)
    print "Dirt Data found at: %08x, len %d " % (sig_add, len(sig_bin))
    dirt_def.dirt_data_paser(sig_bin)


def debug_termination():
    # term = TermHandler(EcdaParser(os.path.join(BB_DIR, "DSPBlackbox-ecda-TCU-7-17-0.txt")))
    term = TermHandler(EcdaParser(os.path.join(BB_DIR, "DSPBlackbox-ecda-TCU-2-14-2.txt")))
    term.go()


def debug_dirt_session():
    get_dirt_data(EcdaParser(os.path.join(BB_DIR, "DSPBlackbox-ecda-TCU-7-17-0.txt")))

if __name__ == '__main__':
    # debug_dirt_session()
    debug_termination()

