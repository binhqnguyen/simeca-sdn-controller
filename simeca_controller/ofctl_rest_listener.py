# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

import json
import ast
import os
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication
from dispatcher import *
from collections import defaultdict

LOG = logging.getLogger('ryu.app.ofctl_rest_listener')
LOG.setLevel(logging.DEBUG)
ENABLE_OVS_GTP = 0

# supported ofctl versions in this restful app
supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
}

# REST API LISTENER FOR IOT CONTROLLER
#
# Install C2S IoT Flow
#
# get the list of all switches
# POST /iot/attach/c2s
# eg, curl -X POST -d arg1=value1 -d arg2=value2 http://<DISPATCHER's IP>:8080/iot/attach/c2s
#
# Install P2P IoT Flow
# POST /iot/attach/p2p
#
# Install C2S HO Flow
# POST /iot/ho/c2s
#
# Install P2P HO Flow
# POST /iot/ho/p2p
#


class RestIoTApi(app_manager.RyuApp):
    SIMECA = "/opt/"
    _SCRIPTS = "%s/simeca" % SIMECA
    DATA="%s/data" % (os.environ['HOME'])
    _CONF = "%s/simeca/CONF" % SIMECA
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }
    def __init__(self, *args, **kwargs):
        super(RestIoTApi, self).__init__(*args, **kwargs)
        LOG.debug("Init RestIoTApi")
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        #LOG.debug("Access switches %s" % kwargs['access_switches'])
        mapper = wsgi.mapper

        #wsgi.registory['StatsController'] = self.data
        wsgi.registory['Dispatcher'] = self.data
        path = '/iot'

        uri = path + '/delete'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='delete_all_flow',
                       conditions=dict(method=['GET']))


        uri = path + '/attach/c2s'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='installIoTFlows',
                       conditions=dict(method=['POST']))

        '''
        Set up a single P2P flow: ismi1 to imsi2
        '''
        uri = path + '/attach/p2p_single'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='installP2PFlows',
                       conditions=dict(method=['POST']))

        '''
        Set up multiple P2P flows between ue_ip and a number of destination UEs.
        '''
        uri = path + '/attach/p2p_multiple'
        #uri = path + '/attach/p2p'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='installP2PFlowsUEs',
                       conditions=dict(method=['POST']))



        uri = path + '/ho/c2s_1'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='installHoFlows_phase1',
                       conditions=dict(method=['POST']))

        uri = path + '/ho/c2s_2'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='installHoFlows_phase2',
                       conditions=dict(method=['POST']))


        uri = path + '/ho/p2p'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='installP2PHoFlows',
                       conditions=dict(method=['POST']))
    
        uri = path + '/ho/p2p_multiple'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='installP2PHoFlowsUEs',
                       conditions=dict(method=['POST']))
 
        uri = path + '/get_routing_id'
        mapper.connect('iot', uri,
                       controller=Dispatcher, action='get_ue_routing_id',
                       conditions=dict(method=['POST']))
    

        self._init_iot_controller_info(kwargs=kwargs)

    '''
    Initialize this IOT controller's information:
    eNBs' ID, eNBs' subnet, UEs' attachment point dictionary, etc
    '''
    def _init_iot_controller_info(self, kwargs):
        LOG.debug("Init IOT controller's info")
        Dispatcher.cnt = 0
        Dispatcher.pkt_cnt = 0
        Dispatcher.record_cnt = 0
        Dispatcher.S1AP_init_request = []
        Dispatcher.S1AP_init_response = []
        Dispatcher.control_rab_info = []
        Dispatcher.ho_info_dict = {}
        Dispatcher.detach_requests = [] #record all detach requests
        Dispatcher.detach_accepts = [] #record all detach accepts
        Dispatcher.RAB_Information = []
        Dispatcher.initiating_msgs = []
        Dispatcher.ueip_to_enb_location_ip = {}
        Dispatcher.p2p_db = {}
        Dispatcher._p2p_list = {}
        Dispatcher.p2p_existed = {}
        Dispatcher.switchname_to_dpid = kwargs['switchname_to_dpid']
        Dispatcher.access_switches = kwargs['access_switches']
        Dispatcher.servers = kwargs['servers']
        Dispatcher.hsw_switches = kwargs['hsw_switches']
        Dispatcher.enb_inf = kwargs['enb_inf']
        Dispatcher.enb2_inf = kwargs['enb2_inf']
        Dispatcher.enb1_port = kwargs['enb_inf']
        Dispatcher.enb2_port = kwargs['enb2_inf']
        Dispatcher.sgw_inf = kwargs['sgw_inf']
        Dispatcher.netd_port = kwargs['sgw_inf']
        Dispatcher.offload_inf = kwargs['offload_inf']
        Dispatcher.dpset = kwargs['dpset']
        #Dispatcher.servers = kwargs['servers']
        
        
        Dispatcher.get_enb_location_ip_map('%s/ENB.data' % self._CONF)
        Dispatcher.ue_to_p2p_destinations = {}
        Dispatcher.get_p2p_attach_destination('%s/P2P_ATTACH.data' % self.DATA)
        #LOG.debug(Dispatcher.enb_location_ip_map)
        Dispatcher.get_imsi_server_name_map('%s/SERVER.data' % self.DATA)
        LOG.debug("Imsi-server map:" % Dispatcher.imsi_server_name_map)
        #LOG.debug("Access switches %s" % Dispatcher.access_switches)
        Dispatcher.locationrouting = LocationRouting(Dispatcher.dpset, Dispatcher.access_switches, Dispatcher.switchname_to_dpid) 
        Dispatcher.access_switch_gtp = AccessSwitchGtp(Dispatcher.dpset, Dispatcher.switchname_to_dpid, Dispatcher.access_switches)
        
        #Dispatcher.attached_ue_ip = open('../iot-controller-eval/e2e_delay_exp/ATTACHED_IP.data','w',0)
        #Dispatcher.p2p_existed_ip = open('../iot-controller-eval/e2e_delay_exp/P2P_IP.data','w',0)
        
        Dispatcher.get_imsi_server_name_map('%s/IMSI_1.data' % (self.DATA))
        Dispatcher.get_imsi_server_name_map('%s/IMSI_2.data' % (self.DATA))
        Dispatcher.get_imsi_server_name_map('%s/IMSI_3.data' % (self.DATA))
	LOG.debug("Got ims_server_name map")

        Dispatcher.imsi_to_ue_ip = {}
        Dispatcher.p2p = {}
        Dispatcher.ue_attached_p2p = defaultdict(list)
        Dispatcher.imsi_to_ip = open ('/tmp/IMSI_IP.log', 'w', 0)
        Dispatcher.imsi_to_ip = open ('/tmp/IMSI_IP.log', 'a', 0)

        #test
        #for i in range(1,300):
        #    Dispatcher._allocate_ipv4('0011040')

        ##Dispatcher._get_MACs()
        Dispatcher.set_default_route_servers()
        #Dispatcher.build_database()
        Dispatcher.del_flows_ryu()
        Dispatcher.push_arp_server()
        #Install prefix shortespath route in SDN core
        Dispatcher.installCoreRoute()

        if ENABLE_OVS_GTP==0:
            #Dispatcher.push_arp_as()
            #Dispatcher.set_static_arp_enb()
            #Dispatcher.set_static_ip_route_enb() #for c2s to work.
            LOG.info("")
        Dispatcher.access_switch_gtp.push_flows_bridging_ryu()
        #for enb_cellid in Dispatcher.enb_location_ip_map:
        #    Dispatcher._set_default_route_enb_prefix('192.190.0.0/16', enb_cellid)
        LOG.info ("-----------IoT listener/dispatcher init DONE: Listening for commands ....---------")
     



    @set_ev_cls([ofp_event.EventOFPStatsReply,
                 ofp_event.EventOFPDescStatsReply,
                 ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPAggregateStatsReply,
                 ofp_event.EventOFPTableStatsReply,
                 ofp_event.EventOFPTableFeaturesStatsReply,
                 ofp_event.EventOFPPortStatsReply,
                 ofp_event.EventOFPQueueStatsReply,
                 ofp_event.EventOFPMeterStatsReply,
                 ofp_event.EventOFPMeterFeaturesStatsReply,
                 ofp_event.EventOFPMeterConfigStatsReply,
                 ofp_event.EventOFPGroupStatsReply,
                 ofp_event.EventOFPGroupFeaturesStatsReply,
                 ofp_event.EventOFPGroupDescStatsReply,
                 ofp_event.EventOFPPortDescStatsReply
                 ], MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls([ofp_event.EventOFPSwitchFeatures,
                 ofp_event.EventOFPQueueGetConfigReply], MAIN_DISPATCHER)
    def features_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        del self.waiters[dp.id][msg.xid]
        lock.set()




