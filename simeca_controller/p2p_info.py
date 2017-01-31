#
#p2p_info
#
class p2p_info:
    def __init__(self, ue_ip="", enb_ip="", sgw_ip="", enb_gtpid="", sgw_gtpid="", ue_imsi="", enb_cellid=""):
        self.ue_ip = ue_ip
        self.enb_ip = enb_ip
        self.sgw_ip = sgw_ip
        self.enb_teid = enb_gtpid
        self.sgw_teid = sgw_gtpid
        self.ue_imsi = ue_imsi
        self.enb_cellid = enb_cellid
