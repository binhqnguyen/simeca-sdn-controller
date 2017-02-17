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
