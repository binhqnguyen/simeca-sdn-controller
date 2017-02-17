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


#!/usr/bin/python
import json
#import requests
import inspect
#
#Flow actions: https://github.com/osrg/ryu/blob/master/ryu/lib/ofctl_v1_3.py (to_action)
#
#Wrapping REST and pycurl.
#
class REST:
	#Destination host address.
	_HTTP_HOST = 'http://0.0.0.0:8080'

	#List of REST's actions declared in the destination Ryu's REST application.
	_REST_ACTIONS = {

		# get the list of all switches
		# GET /stats/switches
		'get_dpids':'/stats/switches',

		# get the desc stats of the switch
		# GET /stats/desc/<dpid>
		'get_desc_stats':'/stats/desc/',

		# get flows stats of the switch
		# GET /stats/flow/<dpid>
		'get_flow_stats':'/stats/flow/',

		# get ports stats of the switch
		# GET /stats/port/<dpid>
		'get_port_stats':'/stats/port/',

		# get meter features stats of the switch
		# GET /stats/meterfeatures/<dpid>
		'get_meter_features':'/stats/meterfeatures/',

		# get meter config stats of the switch
		# GET /stats/meterconfig/<dpid>
		'get_meter_config':'/stats/meterconfig/',

		# get meters stats of the switch
		# GET /stats/meter/<dpid>
		'get_meter_stats':'/stats/meter/',

		# get group features stats of the switch
		# GET /stats/groupfeatures/<dpid>
		'get_group_features':'/stats/groupfeatures/',

		# get groups desc stats of the switch
		# GET /stats/groupdesc/<dpid>
		'get_group_desc':'/stats/groupdesc/',

		# get groups stats of the switch
		# GET /stats/group/<dpid>
		'get_group_stats':'/stats/group/',

		########## Update the switch stats ##########
		#
		# add a flow entry
		# POST /stats/flowentry/add
		'add_flow_entry':'/stats/flowentry/add',

		# modify all matching flow entries
		# POST /stats/flowentry/modify
		'mod_flow_entry':'/stats/flowentry/modify',

		# delete all matching flow entries
		# POST /stats/flowentry/delete
		'delete_match_flow_entry':'/stats/flowentry/delete',

		# delete all flow entries of the switch
		# DELETE /stats/flowentry/clear/<dpid>
		'delete_all_flow_entry':'/stats/flowentry/clear/',

		# add a meter entry
		# POST /stats/meterentry/add
		'add_meter_entry':'/stats/meterentry/add',

		# modify a meter entry
		# POST /stats/meterentry/modify
		'mod_meter_entry':'/stats/meterentry/modify',

		# delete a meter entry
		# POST /stats/meterentry/delete
		'del_meter_entry':'/stats/meterentry/delete',

		# add a group entry
		# POST /stats/groupentry/add
		'add_group_entry':'/stats/groupentry/add',

		# modify a group entry
		# POST /stats/groupentry/modify
		'modify_group_entry':'/stats/groupentry/modify',

		# delete a group entry
		# POST /stats/groupentry/delete
		'del_group_entry':'/stats/groupentry/delete',
		#
		# send a experimeter message
		# POST /stats/experimenter/<dpid>
		'send_experimenter':'/stats/experimenter/'

	}
	
	def __init__ (self, remote_ip):
		self._HTTP_HOST = "http://%s:8080" % remote_ip
	#
	#Add a flow into flow-table
	#
	def add_flows (self, dpid, flow):
		flow['dpid'] = dpid
		r = requests.post(self._HTTP_HOST+self._REST_ACTIONS['add_flow_entry'], json.dumps(flow))
		return r
	

	#
	#Modify all matching flows entry.
	#Note: 
	#	- 2 matched flows are 2 flows that have the same "match" field.
	#	- flow modification does not change timeouts field but "actions", "match" fields. 
	def modify_matching_flow (self, dpid, flow):
		flow['dpid'] = dpid
		return requests.post(self._HTTP_HOST+self._REST_ACTIONS['mod_flow_entry'], json.dumps(flow))

	#Clear all flows on a switch
	def del_flows (self, dpid):
		return requests.delete(self._HTTP_HOST+self._REST_ACTIONS['delete_all_flow_entry']+ str(dpid))

	#Delete all flows that match the "flow" input.
	def del_matching_flows (self, dpid, flow):
		flow['dpid'] = dpid
		return requests.post(self._HTTP_HOST+self._REST_ACTIONS['delete_match_flow_entry'],json.dumps(flow))

	#
	#Dump-flows in a specific switch
	#
	def dump_flows (self, dpid):
		return requests.get(self._HTTP_HOST+self._REST_ACTIONS['get_flow_stats']+ str(dpid))


	#
	#Get switch (datapath) ID.
	#
	def get_dpids (self):
		return requests.get(self._HTTP_HOST+self._REST_ACTIONS['get_dpids'])


if __name__ == "__main__":
	###Testing: 
		#add/del a flow, del all flow past.
		#modify a flow past.
	"""
	if len(sys.argv) != 2:
		print "Parameter: <interface to listen to, eg. eth4>"
		exit(1)
	"""
	rest = REST("0.0.0.0")
	dpids = rest.get_dpids()
	print dpids
	flow_1 = {
		'match':{
			'in_port':1, #switch's port 
		},
		'idle_timeout':999, 
		'hard_timeout':111,
		'actions':[
			{
				"type":"OUTPUT",
				"port":2
			}
		]
	}
	flow_2 = {
		'match':{
				'in_port':2, #switch's port
		},
		'idle_timeout':222,
		'hard_timeout':333,
		'actions':[
				{
						"type":"OUTPUT",
						"port":3
				}
		]
	}
	print rest.get_dpids()
	print "add flow %s" %rest.add_flows(17779080870,flow_2)
	print "mod flow %s " % rest.modify_matching_flow(17779080870,flow_1)
	print "add flow %s " % rest.add_flows(17779080870,flow_2)
	print rest.dump_flows(17779080870).text
	print "del match = %s" % rest.del_matching_flows(17779080870,flow_2)
	print "del flows = %s" %rest.del_flows(17779080870)
	print "after deletion = %s" % rest.dump_flows(17779080870)



	


