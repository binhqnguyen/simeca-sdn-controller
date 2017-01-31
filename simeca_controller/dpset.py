class Dpset:
    dpset = {}
    #def __init__(self):

    def add(self, dp):
        if dp.dpid not in self.dpset:
            self.dpset[int(dp.dpid)] = dp

    def get(self, dpid):
        if int(dpid) not in self.dpset:
            return None, None, None
        else:
            return self.dpset[dpid].dp, self.dpset[dpid].of, self.dpset[dpid].ofp
    def get_all_dpid(self):
        dpid_list = []
        if len(self.dpset) == 0:
            return None
        else:
            return [dpid for dpid in self.dpset]
