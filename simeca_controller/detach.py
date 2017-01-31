#
#Detach request message
#
class Detach_request:
  """docstring for ClassName"""
  DETACH_REQUEST_MSG_TYPE= 45
  def __init__(self, ue_mme_id = "", ue_enb_id="", switch_off="", detach_type_ul="", type_of_id=1, IMSI=""):
    self.ue_mme_id = ue_mme_id
    self.ue_enb_id = ue_enb_id
    self.switch_off = switch_off
    self.detach_type_ul = detach_type_ul
    self.type_of_id = type_of_id #IMSI=1
    self.IMSI = IMSI


  def print_all(self):
    print "ue_mme_id = %s\n" % self.ue_mme_id
    print "ue_enb_id = %s\n" % self.ue_enb_id
    print "switch_off = %s\n" % self.switch_off
    print "detach_type_ul = %s\n" % self.detach_type_ul
    print "type_of_id = %s\n" % self.type_of_id
    print "IMSI = %s\n" % self.IMSI

#
#Detach accept message
#
class Detach_accept:
  """docstring for ClassName"""
  DETACH_ACCEPT_MSG_TYPE= 46
  def __init__(self, ue_mme_id = "", ue_enb_id=""):
    self.ue_mme_id = ue_mme_id
    self.ue_enb_id = ue_enb_id

  def print_all(self):
    print "ue_mme_id = %s\n" % self.ue_mme_id
    print "ue_enb_id = %s\n" % self.ue_enb_id