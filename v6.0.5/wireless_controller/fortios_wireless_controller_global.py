#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_wireless_controller_global
short_description: Configure wireless controller global settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify wireless_controller feature and global category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.5
version_added: "2.9"
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    host:
        description:
            - FortiOS or FortiGate IP address.
        type: str
        required: true
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    wireless_controller_global:
        description:
            - Configure wireless controller global settings.
        default: null
        type: dict
        suboptions:
            ap_log_server:
                description:
                    - Enable/disable configuring APs or FortiAPs to send log messages to a syslog server (default = disable).
                choices:
                    - enable
                    - disable
            ap_log_server_ip:
                description:
                    - IP address that APs or FortiAPs send log messages to.
            ap_log_server_port:
                description:
                    - Port that APs or FortiAPs send log messages to.
            control_message_offload:
                description:
                    - Configure CAPWAP control message data channel offload.
                choices:
                    - ebp-frame
                    - aeroscout-tag
                    - ap-list
                    - sta-list
                    - sta-cap-list
                    - stats
                    - aeroscout-mu
            data_ethernet_II:
                description:
                    - Configure the wireless controller to use Ethernet II or 802.3 frames with 802.3 data tunnel mode (default = disable).
                choices:
                    - enable
                    - disable
            discovery_mc_addr:
                description:
                    - Multicast IP address for AP discovery (default = 244.0.1.140).
            fiapp_eth_type:
                description:
                    - Ethernet type for Fortinet Inter_Access Point Protocol (IAPP), or IEEE 802.11f, packets (0 _ 65535, default = 5252).
            image_download:
                description:
                    - Enable/disable WTP image download at join time.
                choices:
                    - enable
                    - disable
            ipsec_base_ip:
                description:
                    - Base IP address for IPsec VPN tunnels between the access points and the wireless controller (default = 169.254.0.1).
            link_aggregation:
                description:
                    - Enable/disable calculating the CAPWAP transmit hash to load balance sessions to link aggregation nodes (default = disable).
                choices:
                    - enable
                    - disable
            location:
                description:
                    - Description of the location of the wireless controller.
            max_clients:
                description:
                    - Maximum number of clients that can connect simultaneously (default = 0, meaning no limitation).
            max_retransmit:
                description:
                    - Maximum number of tunnel packet retransmissions (0 _ 64, default = 3).
            mesh_eth_type:
                description:
                    - Mesh Ethernet identifier included in backhaul packets (0 _ 65535, default = 8755).
            name:
                description:
                    - Name of the wireless controller.
            rogue_scan_mac_adjacency:
                description:
                    - Maximum numerical difference between an AP's Ethernet and wireless MAC values to match for rogue detection (0 _ 31, default = 7).
            wtp_share:
                description:
                    - Enable/disable sharing of WTPs between VDOMs.
                choices:
                    - enable
                    - disable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
   ssl_verify: "False"
  tasks:
  - name: Configure wireless controller global settings.
    fortios_wireless_controller_global:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wireless_controller_global:
        ap_log_server: "enable"
        ap_log_server_ip: "<your_own_value>"
        ap_log_server_port: "5"
        control_message_offload: "ebp-frame"
        data_ethernet_II: "enable"
        discovery_mc_addr: "<your_own_value>"
        fiapp_eth_type: "9"
        image_download: "enable"
        ipsec_base_ip: "<your_own_value>"
        link_aggregation: "enable"
        location: "<your_own_value>"
        max_clients: "14"
        max_retransmit: "15"
        mesh_eth_type: "16"
        name: "default_name_17"
        rogue_scan_mac_adjacency: "18"
        wtp_share: "enable"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortios.fortios import FortiOSHandler
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password, verify=ssl_verify)


def filter_wireless_controller_global_data(json):
    option_list = ['ap_log_server', 'ap_log_server_ip', 'ap_log_server_port',
                   'control_message_offload', 'data_ethernet_II', 'discovery_mc_addr',
                   'fiapp_eth_type', 'image_download', 'ipsec_base_ip',
                   'link_aggregation', 'location', 'max_clients',
                   'max_retransmit', 'mesh_eth_type', 'name',
                   'rogue_scan_mac_adjacency', 'wtp_share']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for elem in data:
            elem = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def wireless_controller_global(data, fos):
    vdom = data['vdom']
    wireless_controller_global_data = data['wireless_controller_global']
    filtered_data = underscore_to_hyphen(filter_wireless_controller_global_data(wireless_controller_global_data))

    return fos.set('wireless-controller',
                   'global',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_wireless_controller(data, fos):

    if data['wireless_controller_global']:
        resp = wireless_controller_global(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "wireless_controller_global": {
            "required": False, "type": "dict",
            "options": {
                "ap_log_server": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "ap_log_server_ip": {"required": False, "type": "str"},
                "ap_log_server_port": {"required": False, "type": "int"},
                "control_message_offload": {"required": False, "type": "str",
                                            "choices": ["ebp-frame", "aeroscout-tag", "ap-list",
                                                        "sta-list", "sta-cap-list", "stats",
                                                        "aeroscout-mu"]},
                "data_ethernet_II": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "discovery_mc_addr": {"required": False, "type": "str"},
                "fiapp_eth_type": {"required": False, "type": "int"},
                "image_download": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "ipsec_base_ip": {"required": False, "type": "str"},
                "link_aggregation": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "location": {"required": False, "type": "str"},
                "max_clients": {"required": False, "type": "int"},
                "max_retransmit": {"required": False, "type": "int"},
                "mesh_eth_type": {"required": False, "type": "int"},
                "name": {"required": False, "type": "str"},
                "rogue_scan_mac_adjacency": {"required": False, "type": "int"},
                "wtp_share": {"required": False, "type": "str",
                              "choices": ["enable", "disable"]}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_wireless_controller(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_wireless_controller(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()