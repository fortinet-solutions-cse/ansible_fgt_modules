#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.basic import AnsibleModule
# Copyright 2018 Fortinet, Inc.
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
module: fortios_system_switch-interface
short_description: Configure software switch interfaces by grouping physical and WiFi interfaces.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system feature and switch-interface category.
      Examples includes all options and need to be adjusted to datasources before usage.
      Tested with FOS: v6.0.2
version_added: "2.6"
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
            - FortiOS or FortiGate ip adress.
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
        default: "root"
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
    system_switch-interface:
        description:
            - Configure software switch interfaces by grouping physical and WiFi interfaces.
        default: null
        suboptions:
            intra-switch-policy:
                description:
                    - Allow any traffic between switch interfaces or require firewall policies to allow traffic between switch interfaces.
                choices:
                    - implicit
                    - explicit
            member:
                description:
                    - Names of the interfaces that belong to the virtual switch.
                suboptions:
                    interface-name:
                        description:
                            - Physical interface name. Source: system.interface.name.
            name:
                description:
                    - Interface name (name cannot be in use by any other interfaces, VLANs, or inter-VDOM links).
                required: true
            span:
                description:
                    - Enable/disable port spanning. Port spanning echoes traffic received by the software switch to the span destination port.
                choices:
                    - disable
                    - enable
            span-dest-port:
                description:
                    - SPAN destination port name. All traffic on the SPAN source ports is echoed to the SPAN destination port. Source: system.interface.name.
            span-direction:
                description:
                    - The direction in which the SPAN port operates, either: rx, tx, or both.
                choices:
                    - rx
                    - tx
                    - both
            span-source-port:
                description:
                    - Physical interface name. Port spanning echoes all traffic on the SPAN source ports to the SPAN destination port.
                suboptions:
                    interface-name:
                        description:
                            - Physical interface name. Source: system.interface.name.
            type:
                description:
                    - Type of switch based on functionality: switch for normal functionality, or hub to duplicate packets to all port members.
                choices:
                    - switch
                    - hub
            vdom:
                description:
                    - VDOM that the software switch belongs to. Source: system.vdom.name.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure software switch interfaces by grouping physical and WiFi interfaces.
    fortios_system_switch-interface:
      host:  "{{  host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      system_switch-interface:
        state: "present"
        intra-switch-policy: "implicit"
        member:
         -
            interface-name: "<your_own_value> (source: system.interface.name)"
        name: "default_name_6"
        span: "disable"
        span-dest-port: "<your_own_value> (source: system.interface.name)"
        span-direction: "rx"
        span-source-port:
         -
            interface-name: "<your_own_value> (source: system.interface.name)"
        type: "switch"
        vdom: "<your_own_value> (source: system.vdom.name)"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: string
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: string
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: string
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: string
  sample: "key1"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: string
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: string
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: string
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: string
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: string
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: string
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: string
  sample: "v5.6.3"

'''

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


def filter_system_switch-interface_data(json):
    option_list = ['intra-switch-policy', 'member', 'name',
                   'span', 'span-dest-port', 'span-direction',
                   'span-source-port', 'type', 'vdom']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_switch-interface(data, fos):
    vdom = data['vdom']
    system_switch-interface_data = data['system_switch-interface']
    filtered_data = filter_system_switch - \
        interface_data(system_switch-interface_data)

    if system_switch-interface_data['state'] == "present":
        return fos.set('system',
                       'switch-interface',
                       data=filtered_data,
                       vdom=vdom)

    elif system_switch-interface_data['state'] == "absent":
        return fos.delete('system',
                          'switch-interface',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_system(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    fos.https('off')
    fos.login(host, username, password)

    methodlist = ['system_switch-interface']
    for method in methodlist:
        if data[method]:
            resp = eval(method)(data, fos)
            break

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": "True"},
        "system_switch-interface": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str"},
                "intra-switch-policy": {"required": False, "type": "str",
                                        "choices": ["implicit", "explicit"]},
                "member": {"required": False, "type": "list",
                           "options": {
                               "interface-name": {"required": False, "type": "str"}
                           }},
                "name": {"required": True, "type": "str"},
                "span": {"required": False, "type": "str",
                         "choices": ["disable", "enable"]},
                "span-dest-port": {"required": False, "type": "str"},
                "span-direction": {"required": False, "type": "str",
                                   "choices": ["rx", "tx", "both"]},
                "span-source-port": {"required": False, "type": "list",
                                     "options": {
                                         "interface-name": {"required": False, "type": "str"}
                                     }},
                "type": {"required": False, "type": "str",
                         "choices": ["switch", "hub"]},
                "vdom": {"required": False, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    try:
        from fortiosapi import FortiOSAPI
    except ImportError:
        module.fail_json(msg="fortiosapi module is required")

    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
