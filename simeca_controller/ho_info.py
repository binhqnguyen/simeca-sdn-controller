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

class S1HoInfo:
    def __init__(self, ue_ip, ue_imsi, ue_mme_id, ue_enb_id, senb_cellid, tenb_cellid, senb_ip, tenb_ip, senb_teid, tenb_teid, sgw_ip, sgw_teid):
        self.ue_ip = ue_ip
        self.ue_imsi = ue_imsi
        self.ue_mme_id = ue_mme_id
        self.ue_enb_id = ue_enb_id
        self.senb_cellid = senb_cellid
        self.tenb_cellid = tenb_cellid
        self.senb_ip = senb_ip
        self.tenb_ip = tenb_ip
        self.senb_teid = senb_teid
        self.tenb_teid = tenb_teid
        self.sgw_ip = sgw_ip
        self.sgw_teid = sgw_teid
