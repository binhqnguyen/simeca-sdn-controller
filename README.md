Copyright University of Utah, and Nokia Bell Labs.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


Overview:
=========
This repo contains SIMECA's SDN controllers source code and scripts to run SIMECA in PhantomNet.
* Tutorial link: `https://wiki.phantomnet.org/wiki/phantomnet/simeca-sdn-based-iot-mobile-edge-cloud-architecture`
Contact: `binh@cs.utah.edu`

Usage:
=====
* ALl detail instructions could be found here: `https://wiki.phantomnet.org/wiki/phantomnet/simeca-sdn-based-iot-mobile-edge-cloud-architecture`


Note:
====
* SIMECA requires a modified OpenEPC's MME component, which is not opensource. Please contact [PhantomNet](https://phantomnet.org/) if you are interested in running SIMECA end-to-end.


Folders:
=======
* `CONF`: configuration files for SIMECA.
* `SCRIPTS`: scripts to boostrap SIMECA controllers and SIMECA's OVS.
* `epc`: scripts to configure and start SIMECA Mobility Functions (MF) and OpenEPC components (eNodeB, UE).
* `hss_provision`: scripts to provision end-user's subscriber information in HSS's database.
* `ryu`: ryu controller source.
* `simeca_controller`: SIMECA's SDN controller (MC).
* `start_scripts`: scripts to configure and start OVS in SIMECA.
* `XML`: xml file storing SIMECA network topology and computing shortest path forwarding.
* `simeca_constants.sh`: constants used in SIMECA.
