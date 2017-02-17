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
#NAS message: InitialContextSetupRequest or "Activate default EPS bearer context request"
#
class NAS_RAB_setup_request:
  def __init__(self, s_gtp_id="", sgw_ip="", TAI=None, GUTI=None, LAI=None, pdn=None, IMSI="", enb_cellid=""):
    self.s_gtp_id = s_gtp_id
    self.sgw_ip = sgw_ip
    self.TAI = TAI
    self.GUTI = GUTI
    self.LAI = LAI
    self.pdn = pdn
    self.IMSI = IMSI
    self.enb_cellid = enb_cellid

  def print_all(self):
    print "s_gtp_id = %s\n" % self.s_gtp_id
    print "sgw_ip = %s\n" % self.sgw_ip
    print "IMSI = %s\n" % self.IMSI
    if (self.TAI):
      print "TAI = (%s,%s,%s)\n" % (self.TAI["MMC"], self.TAI["MNC"], self.TAI["TAC"])
    if (self.GUTI):
      print "GUTI = (%s,%s,%s,%s,%s)\n" % (self.GUTI["MMC"], self.GUTI["MNC"], self.GUTI["MME_GID"], self.GUTI["MME_CODE"], self.GUTI["M_TMSI"])
    if (self.LAI):
      print "LAI = (%s,%s,%s)\n" % (self.LAI["MMC"],self.LAI["MNC"],self.LAI["LAC"])
    if (self.pdn):
      print "pdn = (%s,%s)\n" % (self.pdn["type"],self.pdn["address"])

#
#NAS message: InitialContextSetupResponse (from eNB)
#
class NAS_RAB_setup_response:
  def __init__(self, e_gtp_id="", enb_ip=None):
    self.e_gtp_id = e_gtp_id
    self.enb_ip = enb_ip

  def print_all(self):
    print "e_gtp_id = %s\n" % self.e_gtp_id
    print "enb_ip = %s\n" % self.enb_ip
