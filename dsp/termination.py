import struct
from c_type_base import *

C_POINTER = c_uint32
PROCESS = c_uint32
C_FUNC_P = c_uint32

SERVICE_T_CONNECTION_C     = 0x00
SERVICE_T_IU_IP_C          = 0x01
SERVICE_T_NB_IP_C          = 0x02
SERVICE_T_NB_TDM_C         = 0x03
SERVICE_T_MB_IP_C          = 0x04
SERVICE_T_A_TDM_C          = 0x05
SERVICE_T_PSTN_TDM_C       = 0x06
SERVICE_T_MB_BB_IP_C       = 0x07
SERVICE_T_IP_PROVIDER_C    = 0x08
SERVICE_T_TONE_GEN_C       = 0x09
SERVICE_T_DTMF_GEN_C       = 0x0A
SERVICE_T_DTMF_DET_C       = 0x0B
SERVICE_T_ANNOUNCEMENT_C   = 0x0C
SERVICE_T_MULTIPARTY_C     = 0x0D
SERVICE_T_ATER_TDM_C       = 0x0E
SERVICE_T_MUX_C            = 0x0F
SERVICE_T_A_IP_C           = 0x10
SERVICE_T_SGW_C            = 0x11
SERVICE_T_PACKET_ATER_IP_C = 0x12
SERVICE_T_MULTIPLIER_C     = 0x13
SERVICE_T_INTERNAL_TERM_C  = 0x14
SERVICE_T_DIAGNOSTICS_C    = 0x15

service_t = {
    0x00: "SERVICE_T_CONNECTION_C    ",
    0x01: "SERVICE_T_IU_IP_C         ",
    0x02: "SERVICE_T_NB_IP_C         ",
    0x03: "SERVICE_T_NB_TDM_C        ",
    0x04: "SERVICE_T_MB_IP_C         ",
    0x05: "SERVICE_T_A_TDM_C         ",
    0x06: "SERVICE_T_PSTN_TDM_C      ",
    0x07: "SERVICE_T_MB_BB_IP_C      ",
    0x08: "SERVICE_T_IP_PROVIDER_C   ",
    0x09: "SERVICE_T_TONE_GEN_C      ",
    0x0A: "SERVICE_T_DTMF_GEN_C      ",
    0x0B: "SERVICE_T_DTMF_DET_C      ",
    0x0C: "SERVICE_T_ANNOUNCEMENT_C  ",
    0x0D: "SERVICE_T_MULTIPARTY_C    ",
    0x0E: "SERVICE_T_ATER_TDM_C      ",
    0x0F: "SERVICE_T_MUX_C           ",
    0x10: "SERVICE_T_A_IP_C          ",
    0x11: "SERVICE_T_SGW_C           ",
    0x12: "SERVICE_T_PACKET_ATER_IP_C",
    0x13: "SERVICE_T_MULTIPLIER_C    ",
    0x14: "SERVICE_T_INTERNAL_TERM_C ",
    0x15: "SERVICE_T_DIAGNOSTICS_C   ",
}

sub_service_t = {
    0x00: "SUBSERVICE_T_CAT1_TRFO_C    ",
    0x01: "SUBSERVICE_T_CAT2_TRFO_C         ",
    0x02: "SUBSERVICE_T_CAT3_TRFO_C         ",
    0x03: "SUBSERVICE_T_CAT1_TC_C        ",
    0x04: "SUBSERVICE_T_CAT2_TC_C         ",
    0x05: "SUBSERVICE_T_CAT3_TC_C         ",
    0x06: "SUBSERVICE_T_ATER_A_C      ",
    0x07: "SUBSERVICE_T_ATER_B_C      ",
    0x08: "SUBSERVICE_T_ATER_C_C   ",
    0x09: "SUBSERVICE_T_ATER_D_C      ",
    0x0A: "SUBSERVICE_T_G_711_C      ",
    0x0B: "SUBSERVICE_T_CS_DATA_C      ",
    0x0C: "SUBSERVICE_T_UNKNOWN_C  ",
    0x0D: "SUBSERVICE_T_EMPTY_C    ",
    0x0E: "SUBSERVICE_T_CONN_AAL1_C      ",
    0x0F: "SUBSERVICE_T_H324M_C           ",
    0x10: "SUBSERVICE_T_H223_H345_C          ",
    0x11: "SUBSERVICE_T_ATER_E_C           ",
    0x12: "SUBSERVICE_T_ATER_F_C",
    0x13: "SUBSERVICE_T_T38_FAX_C    ",
    0x14: "SUBSERVICE_T_T38_TRANS_C ",
    0x15: "SUBSERVICE_T_G_711_10MS_C   ",
    0x16: "SUBSERVICE_T_CAT2_WBTC_C   ",
    0x17: "SUBSERVICE_T_IWBC_C   ",
    0x18: "SUBSERVICE_T_MEDIA_RELAY_C   ",
    0x19: "SUBSERVICE_T_PT_TRANS_C   ",
}


class fw_handler_data_t(MyStruct):
    _fields_ = [
        ("internal", C_POINTER)]


class fw_shared_data_t(MyStruct):
    _fields_ = [
        ("event_pool", C_POINTER),
        ("timeouts", C_POINTER),
        ("termination", C_POINTER),
        ("controller", C_POINTER),
        ("own_process_id", PROCESS),
        ("ext_if_timestamp_freq_khz", c_uint16),
        ("ext_if_interval_ms", c_uint16),
        ("ext_if_conn_number", c_uint16),
        ("transmitter_timeout_handle", c_uint16),
        ("stream_mode", c_uint16),
        ("ext_codec", c_uint16),
        ("not_care", c_uint16),
        ("ecref_write", C_FUNC_P),
        ("ecref_reset", C_POINTER),
        ("ecref_data", C_POINTER),
        ("num_sent_packets", c_uint32)]


class internal_termination_data(MyStruct):
    _fields_ = [
        ("shared", fw_shared_data_t),
        ("error_handler", C_POINTER),
        ("controller_master", fw_handler_data_t),
        ("int_ifh_master", fw_handler_data_t),
        ("ext_ifh_master", fw_handler_data_t),
        ("tlph_master", fw_handler_data_t),
        ("upph_master", fw_handler_data_t),
        ("uph_master", fw_handler_data_t),
        ("jbfh_master", fw_handler_data_t),
        ("dmxh_master", fw_handler_data_t),
        ("state", c_uint16)]



class TermShared(object):
    def __init__(self, shared, ecda):
        self.shared = shared
        self.ecda = ecda

    def fw_lib_get_cc_params(self):
        p_controller = self.shared.controller
        sig = self.ecda.find_singal_by_address(p_controller)
        return sig[0x478:]

    def cc_is_ip_termination(self):
        cc_params = self.fw_lib_get_cc_params()
        unpack_cc = struct.unpack("3B", cc_params[:3])
        s, ss, sss = unpack_cc

        if s in [SERVICE_T_MB_IP_C, SERVICE_T_MB_BB_IP_C, SERVICE_T_NB_IP_C,
                 SERVICE_T_IU_IP_C, SERVICE_T_A_IP_C, SERVICE_T_PACKET_ATER_IP_C]:
            s = service_t[s]
            ss = sub_service_t[ss]
            print "%s %s %x" % (s, ss, sss)
            return True


class Handler(object):
    def __init__(self, ecda_obj):
        self.ecda = ecda_obj

    def find_int_term_data(self):
        pid = self.ecda.find_process_id("master")
        signals = self.ecda.find_signal(sig_no=None, sender=pid, addr=pid, owner=pid, pool=None, size=92)

        for _sig in signals:
            sig_no, sender, addr, owner, pool, size, data = _sig
            # print sig_no, sender, addr, owner, pool, size, len(data)
            # print data
            sig_add, sig_bin = self.ecda.pack_signal_data(data)
            sig = unpack_bin_to_sig(internal_termination_data, sig_bin)
            # print
            term_shared = TermShared(sig.shared, self.ecda)
            sig.log_it(None, "sig")
            # if term_shared.cc_is_ip_termination():
            #     sig.log_it(None, "sig")

    def go(self):
        self.find_int_term_data()
