from ctypes import *
import re
import struct


class MyPrint(object):
    def log_it(self, off, prefix=""):
        if prefix == "":
            prefix = "%s" % self

        if off is None:
            off = 0

        for var in self._fields_:
            key = var[0]
            val = getattr(self, key)

            c_type = var[1]
            cur_prefix = prefix + "." + key

            if isinstance(val, Array):
                for i in range(len(val)):
                    if isinstance(val[i], Structure) or isinstance(val, Union):
                        val[i].log_it(off, cur_prefix + "[%d]" % i)
                    else:
                        print "[0x%x] %s[%d] = %s" % (off, cur_prefix, i, hex(val[i]))
                off += sizeof(c_type)

            elif isinstance(val, Structure) or isinstance(val, Union):
                val.log_it(off, cur_prefix)
                off += sizeof(c_type)
            else:
                print "[0x%x] %s = %s" % (off, cur_prefix, hex(val))
                off += sizeof(c_type)


class MyStruct(BigEndianStructure, MyPrint):
    """
    Internal structure have 4-byte alignment
    """
    _pack_ = 4

    def pack(self):
        return string_at(byref(self), sizeof(self))


class MyUnion(Union, MyPrint):
    _pack_ = 4

    def pack(self):
        return string_at(byref(self), sizeof(self))


# Built in type define
class Example(MyStruct):
    _fields_ = [("computer", c_uint16),
                ("family", c_uint16),
                ("process_id", c_uint16),
                ("focus", c_uint8)]


def unpack_bin_to_sig(c_type, buf):
    s_string = create_string_buffer(buf)
    return cast(pointer(s_string), POINTER(c_type)).contents


def unpack_txt_to_sig(c_type, buf):
    fmt = "!%dB" % len(buf)
    raw_data = struct.pack(fmt, *buf)
    return unpack_bin_to_sig(c_type, raw_data)


def unpack_mon_to_sig(mon):
    p = re.compile("MONITORED MESSAGE: \w{4} \w{4} \w{4} \w{4} \w{2} \w{2} \w{4} (\w{4}) \w{4}(.*)", re.DOTALL)

    m = re.findall(p, mon)
    sig_no, raw_data = m[0]

    sig_no = int(sig_no, 16)
    raw_txt = map(lambda x: int(x, 16), raw_data.split())
    return sig_no, unpack_txt_to_sig(SIGNAL_LIST[sig_no], raw_txt)