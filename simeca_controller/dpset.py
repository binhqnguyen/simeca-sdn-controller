#Copyright Binh Nguyen University of Utah (binh@cs.utah.edu)
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

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
