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
#
# the lib use python logging can get it if the following is set in your
# Ansible config.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_system_vxlan
short_description: Configure VXLAN devices in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and vxlan category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.2
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
            - FortiOS or FortiGate ip address.
       required: true
    username:
        description:
            - FortiOS or FortiGate username.
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
        type: bool
        default: true
    system_vxlan:
        description:
            - Configure VXLAN devices.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            dstport:
                description:
                    - VXLAN destination port (1 - 65535, default = 4789).
            interface:
                description:
                    - Outgoing interface for VXLAN encapsulated traffic. Source system.interface.name.
            ip-version:
                description:
                    - IP version to use for the VXLAN interface and so for communication over the VXLAN. IPv4 or IPv6 unicast or multicast.
                choices:
                    - ipv4-unicast
                    - ipv6-unicast
                    - ipv4-multicast
                    - ipv6-multicast
            multicast-ttl:
                description:
                    - VXLAN multicast TTL (1-255, default = 0).
            name:
                description:
                    - VXLAN device or interface name. Must be a unique interface name.
                required: true
            remote-ip:
                description:
                    - IPv4 address of the VXLAN interface on the device at the remote end of the VXLAN.
                suboptions:
                    ip:
                        description:
                            - IPv4 address.
                        required: true
            remote-ip6:
                description:
                    - IPv6 IP address of the VXLAN interface on the device at the remote end of the VXLAN.
                suboptions:
                    ip6:
                        description:
                            - IPv6 address.
                        required: true
            vni:
                description:
                    - VXLAN network ID.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure VXLAN devices.
    fortios_system_vxlan:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_vxlan:
        state: "present"
        dstport: "3"
        interface: "<your_own_value> (source system.interface.name)"
        ip-version: "ipv4-unicast"
        multicast-ttl: "6"
        name: "default_name_7"
        remote-ip:
         -
            ip: "<your_own_value>"
        remote-ip6:
         -
            ip6: "<your_own_value>"
        vni: "12"
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

fos = None


def login(data):
    host = data['host']
    username = data['username']
    password = data['password']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password)


def filter_system_vxlan_data(json):
    option_list = ['dstport', 'interface', 'ip-version',
                   'multicast-ttl', 'name', 'remote-ip',
                   'remote-ip6', 'vni']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_multilists_attributes(data):
    multilist_attrs = []

    for attr in multilist_attrs:
        try:
            path = "data['" + "']['".join(elem for elem in attr) + "']"
            current_val = eval(path)
            flattened_val = ' '.join(elem for elem in current_val)
            exec(path + '= flattened_val')
        except BaseException:
            pass

    return data


def system_vxlan(data, fos):
    vdom = data['vdom']
    system_vxlan_data = data['system_vxlan']
    flattened_data = flatten_multilists_attributes(system_vxlan_data)
    filtered_data = filter_system_vxlan_data(flattened_data)
    if system_vxlan_data['state'] == "present":
        return fos.set('system',
                       'vxlan',
                       data=filtered_data,
                       vdom=vdom)

    elif system_vxlan_data['state'] == "absent":
        return fos.delete('system',
                          'vxlan',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    if data['system_vxlan']:
        resp = system_vxlan(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_vxlan": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "dstport": {"required": False, "type": "int"},
                "interface": {"required": False, "type": "str"},
                "ip-version": {"required": False, "type": "str",
                               "choices": ["ipv4-unicast", "ipv6-unicast", "ipv4-multicast",
                                           "ipv6-multicast"]},
                "multicast-ttl": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "remote-ip": {"required": False, "type": "list",
                              "options": {
                                  "ip": {"required": True, "type": "str"}
                              }},
                "remote-ip6": {"required": False, "type": "list",
                               "options": {
                                   "ip6": {"required": True, "type": "str"}
                               }},
                "vni": {"required": False, "type": "int"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    try:
        from fortiosapi import FortiOSAPI
    except ImportError:
        module.fail_json(msg="fortiosapi module is required")

    global fos
    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
