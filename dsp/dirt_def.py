import struct

L_SYS_MAX_NUM_SERVICES = 120
MAX_NUM_OF_RTCP_SESSIONS = L_SYS_MAX_NUM_SERVICES


class RtcpSessionTable(object):
    def __init__(self):
        self.fiter = None
        self.service_id = [None] * MAX_NUM_OF_RTCP_SESSIONS
        self.rx_conn_number = [None] * MAX_NUM_OF_RTCP_SESSIONS
        self.rtcp_session_p = [None] * MAX_NUM_OF_RTCP_SESSIONS

    def set_filter(self, service_id):
        self.fiter = service_id

    def __str__(self):
        _str = ""
        for i in range(MAX_NUM_OF_RTCP_SESSIONS):
            if self.fiter is None:
                _str += "service id: %08x, *session=%08x\n" % (self.service_id[i], self.rtcp_session_p[i])
            elif self.service_id[i] == self.fiter:
                _str += "service id: %08x, *session=%08x\n" % (self.service_id[i], self.rtcp_session_p[i])
        return _str


FMT_SEESION_TABLE = ">{num_of_session}I{num_of_session}H{num_of_session}I"
FMT_SEESION_TABLE = FMT_SEESION_TABLE.format(num_of_session="%d" % MAX_NUM_OF_RTCP_SESSIONS)


def get_rtcp_session_table(dirt):
    """
    :param dirt_data: The packed data for struct dirt_data
    :return:
    """
    session_table_off = 0x6c
    session_table_len = struct.calcsize(FMT_SEESION_TABLE)
    session = struct.unpack(FMT_SEESION_TABLE, dirt[session_table_off:(session_table_off+session_table_len)])
    rtcp_session_table = RtcpSessionTable()
    for i in range(MAX_NUM_OF_RTCP_SESSIONS):
        rtcp_session_table.service_id[i] = session[i]
        rtcp_session_table.rx_conn_number[i] = session[i+MAX_NUM_OF_RTCP_SESSIONS]
        rtcp_session_table.rtcp_session_p[i] = session[i+MAX_NUM_OF_RTCP_SESSIONS*2]

    return rtcp_session_table


def dirt_data_paser(dirt):
    pid = struct.unpack(">I", dirt[0:4])
    print "Dirt PID = %08x" % pid
    rtcp_session_table = get_rtcp_session_table(dirt)
    rtcp_session_table.set_filter(0x0D01BAC0)
    print rtcp_session_table


