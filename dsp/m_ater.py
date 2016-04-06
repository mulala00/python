import os
import sys
import struct
from ecda import EcdaParser
from c_type_base import *


class m_ater_data_io(MyStruct):
    _fields_ = [
        ("events", c_uint16, 3),
        ("direction", c_uint16, 1),
        ("is_tone", c_uint16, 1),
        ("is_amr_hr", c_uint16, 1),
        ("is_rif", c_uint16, 1),
        ("is_codec_change_for_real", c_uint16, 1),
        ("spare", c_uint16, 8),
        ("mode_set", c_uint16),
        ("data_size_8", c_uint16 * 4),
        ("data", c_uint32 * 4)]


class m_ater_control_input(MyStruct):
    _fields_ = [
        ("is_upm_request_event", c_uint16, 1),
        ("is_amrwb_needed_ack_event", c_uint16, 1),
        ("is_get_service_state_event", c_uint16, 1),
        ("is_set_service_state_event", c_uint16, 1),
        ("is_tfo_indication_event", c_uint16, 1),
        ("is_optimal_config_event", c_uint16, 1),
        ("is_set_gcf_state_event", c_uint16, 1),
        ("is_rate_control_event", c_uint16, 1),
        ("tfo_indication", c_uint16, 1),
        ("cmr", c_uint16, 4),
        ("spare", c_uint16, 3),
        ("*upm", c_uint32)]


def show_ingress_buffer(sig):
    offset = 0x14
    buffer_len = 20
    buffer_num = 8

    for i in range(buffer_num):
        sync_ingress_buffer = sig[offset: offset+buffer_len*2]
        sync_ingress_buffer = struct.unpack("20H", sync_ingress_buffer)
        f_s = "  %04x " * buffer_len
        print f_s % sync_ingress_buffer
        offset += buffer_len*2
    print


def show_egress_buffer(sig):
    offset = 0x154
    buffer_len = 20
    buffer_num = 8

    for i in range(buffer_num):
        sync_egress_buffer = sig[offset: offset+buffer_len*2]
        sync_egress_buffer = struct.unpack("20H", sync_egress_buffer)
        f_s = "  %04x " * buffer_len
        print f_s % sync_egress_buffer
        offset += buffer_len*2
    print


def show_param(sig):
    p_sync = struct.unpack(">I", sig[:4])
    print "* sync = %x" % p_sync
    GLO_SYNC_POINTER.append(p_sync)


def show_egress_buffer_pointer(sig):
    offset = 0x28
    buffer_num = 8

    egress_buffer = sig[offset: offset+8*4]
    egress_buffer = struct.unpack(">8I", egress_buffer)

    if (egress_buffer[0] - 0x154) not in GLO_M_SYNC_DATA_ADD:
        print "Error"
        print map(lambda x: "%x" % x, GLO_M_SYNC_DATA_ADD)
    print "   internal_ater_data %x" % (egress_buffer[0] - 0x154)

    for i in range(buffer_num):
        print "  *egress_snyc_buffer[%d] = %x" % (i, egress_buffer[i])
    print


def unpack_to_internal_ater_data(sig):
    show_param(sig)
    # show_ingress_buffer(sig)
    # show_egress_buffer(sig)


def unpack_to_m_ater_sync_params(sig):
    show_egress_buffer_pointer(sig)


GLO_M_SYNC_DATA_ADD = []
GLO_SYNC_POINTER = []


def find_internal_ater_data(ecda_obj):
    pid = ecda_obj.find_process_id("master")
    signals = ecda_obj.find_signal(sig_no=None, sender=pid, addr=pid, owner=None, pool=None, size=776)

    for _sig in signals:
        sig_no, sender, addr, owner, pool, size, data = _sig

        sig_add, sig_bin = ecda_obj.pack_signal_data(data)
        print sig_no, sender, addr, owner, pool, size, len(data), "@: %x" % sig_add
        unpack_to_internal_ater_data(sig_bin)


def find_m_ater_sync_params(ecda_obj):
    pid = ecda_obj.find_process_id("master")
    signals = ecda_obj.find_signal(sig_no=None, sender=pid, addr=pid, owner=None, pool=None, size=512)

    for _sig in signals:
        sig_no, sender, addr, owner, pool, size, data = _sig

        sig_add, sig_bin = ecda_obj.pack_signal_data(data)
        print sig_no, sender, addr, owner, pool, size, len(data), "@: %x" % sig_add
        unpack_to_m_ater_sync_params(sig_bin)
        GLO_M_SYNC_DATA_ADD.append(sig_add)


def unpack_m_ater_data(sig):
    p_internal = struct.unpack(">I", sig[0xa4:0xa8])[0]
    data_in_bits = struct.unpack(">H", sig[0x8:0xa])[0]

    data_in = unpack_bin_to_sig(m_ater_data_io, sig[0x8:0x24])
    # data_in.log_it(None, "data_in")

    # for i in range(4):
    #     print "data_in.data_size_8[%d] = %x, *data[%d] = %x" % (i, data_in.data_size_8[i], i, data_in.data[i])

    data_out = unpack_bin_to_sig(m_ater_data_io, sig[0x24:0x40])
    # data_out.log_it(None, "data_out")

    control_in = unpack_bin_to_sig(m_ater_control_input, sig[0x40:0x48])
    control_in.log_it(None, "control_in")

    # for i in range(4):
    #     print "data_out.data_size_8[%d] = %x, *data[%d] = %x" % (i, data_out.data_size_8[i], i, data_out.data[i])

    print "* internal = %x" % p_internal
    GLO_SYNC_POINTER.append(p_internal)


def find_m_ater_data(ecda_obj):
    pid = ecda_obj.find_process_id("master")
    signals = ecda_obj.find_signal(sig_no=None, sender=pid, addr=pid, owner=None, pool=None, size=168)

    for _sig in signals:
        sig_no, sender, addr, owner, pool, size, data = _sig

        sig_add, sig_bin = ecda_obj.pack_signal_data(data)
        print sig_no, sender, addr, owner, pool, size, len(data), "@: %x" % sig_add
        unpack_m_ater_data(sig_bin)


def debug_m_ater(ecda):
    print "\n", ecda
    ecda_obj = EcdaParser(ecda)
    print "==== m_ater_data ===="
    find_m_ater_data(ecda_obj)

    # print "\n==== internal_ater_data ===="
    # find_internal_ater_data(ecda_obj)


if __name__ == '__main__':
    debug_m_ater(r"logs\DSPBlackbox-ecda-TCU-23-16-3.txt")
    debug_m_ater(r"logs\DSPBlackbox-ecda-TCU-23-16-5.txt")
    debug_m_ater(r"logs\DSPBlackbox-ecda-TCU-23-16-0.txt")
    debug_m_ater(r"logs\DSPBlackbox-ecda-TCU-2-14-2.txt")
