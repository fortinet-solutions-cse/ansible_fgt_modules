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
module: fortios_switch_controller_lldp_profile
short_description: Configure FortiSwitch LLDP profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify switch_controller feature and lldp_profile category.
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
    ssl_verify:
        description:
            - Ensures FortiGate certificate must be verified by a proper CA.
        type: bool
        default: true
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        choices:
            - present
            - absent
    switch_controller_lldp_profile:
        description:
            - Configure FortiSwitch LLDP profiles.
        default: null
        type: dict
        suboptions:
            802.1_tlvs:
                description:
                    - Transmitted IEEE 802.1 TLVs.
                choices:
                    - port-vlan-id
            802.3_tlvs:
                description:
                    - Transmitted IEEE 802.3 TLVs.
                choices:
                    - max-frame-size
            auto_isl:
                description:
                    - Enable/disable auto inter_switch LAG.
                choices:
                    - disable
                    - enable
            auto_isl_hello_timer:
                description:
                    - Auto inter_switch LAG hello timer duration (1 _ 30 sec, default = 3).
            auto_isl_port_group:
                description:
                    - Auto inter_switch LAG port group ID (0 _ 9).
            auto_isl_receive_timeout:
                description:
                    - Auto inter_switch LAG timeout if no response is received (3 _ 90 sec, default = 9).
            custom_tlvs:
                description:
                    - Configuration method to edit custom TLV entries.
                suboptions:
                    information_string:
                        description:
                            - Organizationally defined information string (0 _ 507 hexadecimal bytes).
                    name:
                        description:
                            - TLV name (not sent).
                        required: true
                    oui:
                        description:
                            - Organizationally unique identifier (OUI), a 3_byte hexadecimal number, for this TLV.
                    subtype:
                        description:
                            - Organizationally defined subtype (0 _ 255).
            med_network_policy:
                description:
                    - Configuration method to edit Media Endpoint Discovery (MED) network policy type_length_value (TLV) categories.
                suboptions:
                    dscp:
                        description:
                            - Advertised Differentiated Services Code Point (DSCP) value, a packet header value indicating the level of service requested for
                               traffic, such as high priority or best effort delivery.
                    name:
                        description:
                            - Policy type name.
                        required: true
                    priority:
                        description:
                            - Advertised Layer 2 priority (0 _ 7; from lowest to highest priority).
                    status:
                        description:
                            - Enable or disable this TLV.
                        choices:
                            - disable
                            - enable
                    vlan:
                        description:
                            - ID of VLAN to advertise, if configured on port (0 _ 4094, 0 = priority tag).
            med_tlvs:
                description:
                    - "Transmitted LLDP_MED TLVs (type_length_value descriptions): inventory management TLV and/or network policy TLV."
                choices:
                    - inventory-management
                    - network-policy
            name:
                description:
                    - Profile name.
                required: true
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
  - name: Configure FortiSwitch LLDP profiles.
    fortios_switch_controller_lldp_profile:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      switch_controller_lldp_profile:
        802.1_tlvs: "port-vlan-id"
        802.3_tlvs: "max-frame-size"
        auto_isl: "disable"
        auto_isl_hello_timer: "6"
        auto_isl_port_group: "7"
        auto_isl_receive_timeout: "8"
        custom_tlvs:
         -
            information_string: "<your_own_value>"
            name: "default_name_11"
            oui: "<your_own_value>"
            subtype: "13"
        med_network_policy:
         -
            dscp: "15"
            name: "default_name_16"
            priority: "17"
            status: "disable"
            vlan: "19"
        med_tlvs: "inventory-management"
        name: "default_name_21"
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


def filter_switch_controller_lldp_profile_data(json):
    option_list = ['802.1_tlvs', '802.3_tlvs', 'auto_isl',
                   'auto_isl_hello_timer', 'auto_isl_port_group', 'auto_isl_receive_timeout',
                   'custom_tlvs', 'med_network_policy', 'med_tlvs',
                   'name']
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


def switch_controller_lldp_profile(data, fos):
    vdom = data['vdom']
    state = data['state']
    switch_controller_lldp_profile_data = data['switch_controller_lldp_profile']
    filtered_data = underscore_to_hyphen(filter_switch_controller_lldp_profile_data(switch_controller_lldp_profile_data))

    if state == "present":
        return fos.set('switch-controller',
                       'lldp-profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('switch-controller',
                          'lldp-profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_switch_controller(data, fos):

    if data['switch_controller_lldp_profile']:
        resp = switch_controller_lldp_profile(data, fos)

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
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "switch_controller_lldp_profile": {
            "required": False, "type": "dict",
            "options": {
                "802.1_tlvs": {"required": False, "type": "str",
                               "choices": ["port-vlan-id"]},
                "802.3_tlvs": {"required": False, "type": "str",
                               "choices": ["max-frame-size"]},
                "auto_isl": {"required": False, "type": "str",
                             "choices": ["disable", "enable"]},
                "auto_isl_hello_timer": {"required": False, "type": "int"},
                "auto_isl_port_group": {"required": False, "type": "int"},
                "auto_isl_receive_timeout": {"required": False, "type": "int"},
                "custom_tlvs": {"required": False, "type": "list",
                                "options": {
                                    "information_string": {"required": False, "type": "str"},
                                    "name": {"required": True, "type": "str"},
                                    "oui": {"required": False, "type": "str"},
                                    "subtype": {"required": False, "type": "int"}
                                }},
                "med_network_policy": {"required": False, "type": "list",
                                       "options": {
                                           "dscp": {"required": False, "type": "int"},
                                           "name": {"required": True, "type": "str"},
                                           "priority": {"required": False, "type": "int"},
                                           "status": {"required": False, "type": "str",
                                                      "choices": ["disable", "enable"]},
                                           "vlan": {"required": False, "type": "int"}
                                       }},
                "med_tlvs": {"required": False, "type": "str",
                             "choices": ["inventory-management", "network-policy"]},
                "name": {"required": True, "type": "str"}

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

            is_error, has_changed, result = fortios_switch_controller(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_switch_controller(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
