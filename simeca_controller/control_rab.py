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
#An entry after matching init and response msgs.
#This entry contains information to:
# 1. Map UE's IP address and uplink GTP TEID (e_GTP_TEID)
# 2. UE's location (TAI).
#
class Control_RAB_Information:
  """docstring for ClassName"""
  def __init__(self, ue_mme_id = "", ue_enb_id="", ue_ip="", e_gtp_id="", s_gtp_id="", enb_ip="", sgw_ip="", TAI=None, LAI=None, GUTI=None, imsi="", enb_cellid=""):
    self.ue_mme_id = ue_mme_id
    self.ue_enb_id = ue_enb_id
    self.ue_ip = ue_ip
    self.e_gtp_id = e_gtp_id
    self.s_gtp_id = s_gtp_id
    self.enb_ip = enb_ip
    self.sgw_ip = sgw_ip
    self.TAI = TAI
    self.LAI = LAI
    self.GUTI = GUTI
    self.imsi = imsi
    self.enb_cellid = enb_cellid

  def print_all(self):
    print "ue_mme_id = %s\n" % self.ue_mme_id
    print "ue_enb_id = %s\n" % self.ue_enb_id
    print "ue_ip = %s\n" % self.ue_ip
    print "e_gtp_id = %s\n" % self.e_gtp_id
    print "s_gtp_id = %s\n" % self.s_gtp_id
    print "enb_ip = %s\n" % self.enb_ip
    print "sgw_ip = %s\n" % self.sgw_ip
    print "IMSI = %s\n" % self.imsi
    print "enb_cellid = %s\n" % self.enb_cellid
    if (self.TAI):
      print "TAI = (%s,%s,%s)\n" % (self.TAI["MMC"], self.TAI["MNC"], self.TAI["TAC"])
    if (self.GUTI):
      print "GUTI = (%s,%s,%s,%s,%s)\n" % (self.GUTI["MMC"], self.GUTI["MNC"], self.GUTI["MME_GID"], self.GUTI["MME_CODE"], self.GUTI["M_TMSI"])
    if (self.LAI):
      print "LAI = (%s,%s,%s)\n" % (self.LAI["MMC"],self.LAI["MNC"],self.LAI["LAC"])
