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
module: fortios_router_policy
short_description: Configure IPv4 routing policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and policy category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.6
version_added: "2.8"
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
        required: false
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: false
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
        version_added: 2.9
    state:
        description:
            - Indicates whether to create or remove the object.
              This attribute was present already in previous version in a deeper level.
              It has been moved out to this outer level.
        type: str
        required: false
        choices:
            - present
            - absent
        version_added: 2.9
    router_policy:
        description:
            - Configure IPv4 routing policies.
        default: null
        type: dict
        suboptions:
            state:
                description:
                    - B(Deprecated)
                    - Starting with Ansible 2.9 we recommend using the top-level 'state' parameter.
                    - HORIZONTALLINE
                    - Indicates whether to create or remove the object.
                type: str
                required: false
                choices:
                    - present
                    - absent
            action:
                description:
                    - Action of the policy route.
                type: str
                choices:
                    - deny
                    - permit
            comments:
                description:
                    - Optional comments.
                type: str
            dst:
                description:
                    - Destination IP and mask (x.x.x.x/x).
                type: list
                suboptions:
                    subnet:
                        description:
                            - IP and mask.
                        required: true
                        type: str
            dst_negate:
                description:
                    - Enable/disable negating destination address match.
                type: str
                choices:
                    - enable
                    - disable
            dstaddr:
                description:
                    - Destination address name.
                type: list
                suboptions:
                    name:
                        description:
                            - Address/group name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            end_port:
                description:
                    - End destination port number (0 - 65535).
                type: int
            end_source_port:
                description:
                    - End source port number (0 - 65535).
                type: int
            gateway:
                description:
                    - IP address of the gateway.
                type: str
            input_device:
                description:
                    - Incoming interface name.
                type: list
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            output_device:
                description:
                    - Outgoing interface name. Source system.interface.name.
                type: str
            protocol:
                description:
                    - Protocol number (0 - 255).
                type: int
            seq_num:
                description:
                    - Sequence number.
                type: int
            src:
                description:
                    - Source IP and mask (x.x.x.x/x).
                type: list
                suboptions:
                    subnet:
                        description:
                            - IP and mask.
                        required: true
                        type: str
            src_negate:
                description:
                    - Enable/disable negating source address match.
                type: str
                choices:
                    - enable
                    - disable
            srcaddr:
                description:
                    - Source address name.
                type: list
                suboptions:
                    name:
                        description:
                            - Address/group name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            start_port:
                description:
                    - Start destination port number (0 - 65535).
                type: int
            start_source_port:
                description:
                    - Start source port number (0 - 65535).
                type: int
            status:
                description:
                    - Enable/disable this policy route.
                type: str
                choices:
                    - enable
                    - disable
            tos:
                description:
                    - Type of service bit pattern.
                type: str
            tos_mask:
                description:
                    - Type of service evaluated bits.
                type: str
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
  - name: Configure IPv4 routing policies.
    fortios_router_policy:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      router_policy:
        action: "deny"
        comments: "<your_own_value>"
        dst:
         -
            subnet: "<your_own_value>"
        dst_negate: "enable"
        dstaddr:
         -
            name: "default_name_9 (source firewall.address.name firewall.addrgrp.name)"
        end_port: "10"
        end_source_port: "11"
        gateway: "<your_own_value>"
        input_device:
         -
            name: "default_name_14 (source system.interface.name)"
        output_device: "<your_own_value> (source system.interface.name)"
        protocol: "16"
        seq_num: "17"
        src:
         -
            subnet: "<your_own_value>"
        src_negate: "enable"
        srcaddr:
         -
            name: "default_name_22 (source firewall.address.name firewall.addrgrp.name)"
        start_port: "23"
        start_source_port: "24"
        status: "enable"
        tos: "<your_own_value>"
        tos_mask: "<your_own_value>"
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


def filter_router_policy_data(json):
    option_list = ['action', 'comments', 'dst',
                   'dst_negate', 'dstaddr', 'end_port',
                   'end_source_port', 'gateway', 'input_device',
                   'output_device', 'protocol', 'seq_num',
                   'src', 'src_negate', 'srcaddr',
                   'start_port', 'start_source_port', 'status',
                   'tos', 'tos_mask']
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


def router_policy(data, fos):
    vdom = data['vdom']
    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['router_policy'] and data['router_policy']:
        state = data['router_policy']['state']
    else:
        state = True
    router_policy_data = data['router_policy']
    filtered_data = underscore_to_hyphen(filter_router_policy_data(router_policy_data))

    if state == "present":
        return fos.set('router',
                       'policy',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('router',
                          'policy',
                          mkey=filtered_data['seq-num'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_router(data, fos):

    if data['router_policy']:
        resp = router_policy(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "default": "", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "state": {"required": False, "type": "str",
                  "choices": ["present", "absent"]},
        "router_policy": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]},
                "action": {"required": False, "type": "str",
                           "choices": ["deny", "permit"]},
                "comments": {"required": False, "type": "str"},
                "dst": {"required": False, "type": "list",
                        "options": {
                            "subnet": {"required": True, "type": "str"}
                        }},
                "dst_negate": {"required": False, "type": "str",
                               "choices": ["enable", "disable"]},
                "dstaddr": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "end_port": {"required": False, "type": "int"},
                "end_source_port": {"required": False, "type": "int"},
                "gateway": {"required": False, "type": "str"},
                "input_device": {"required": False, "type": "list",
                                 "options": {
                                     "name": {"required": True, "type": "str"}
                                 }},
                "output_device": {"required": False, "type": "str"},
                "protocol": {"required": False, "type": "int"},
                "seq_num": {"required": False, "type": "int"},
                "src": {"required": False, "type": "list",
                        "options": {
                            "subnet": {"required": True, "type": "str"}
                        }},
                "src_negate": {"required": False, "type": "str",
                               "choices": ["enable", "disable"]},
                "srcaddr": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "start_port": {"required": False, "type": "int"},
                "start_source_port": {"required": False, "type": "int"},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "tos": {"required": False, "type": "str"},
                "tos_mask": {"required": False, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    # legacy_mode refers to using fortiosapi instead of HTTPAPI
    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_router(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_router(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
