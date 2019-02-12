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
module: fortios_system_gre_tunnel
short_description: Configure GRE tunnel in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system feature and gre_tunnel category.
      Examples includes all options and need to be adjusted to datasources before usage.
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
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
        type: bool
        default: true
    system_gre_tunnel:
        description:
            - Configure GRE tunnel.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            checksum-reception:
                description:
                    - Enable/disable validating checksums in received GRE packets.
                choices:
                    - disable
                    - enable
            checksum-transmission:
                description:
                    - Enable/disable including checksums in transmitted GRE packets.
                choices:
                    - disable
                    - enable
            dscp-copying:
                description:
                    - Enable/disable DSCP copying.
                choices:
                    - disable
                    - enable
            interface:
                description:
                    - Interface name. Source system.interface.name.
            ip-version:
                description:
                    - IP version to use for VPN interface.
                choices:
                    - 4
                    - 6
            keepalive-failtimes:
                description:
                    - Number of consecutive unreturned keepalive messages before a GRE connection is considered down (1 - 255).
            keepalive-interval:
                description:
                    - Keepalive message interval (0 - 32767, 0 = disabled).
            key-inbound:
                description:
                    - Require received GRE packets contain this key (0 - 4294967295).
            key-outbound:
                description:
                    - Include this key in transmitted GRE packets (0 - 4294967295).
            local-gw:
                description:
                    - IP address of the local gateway.
            local-gw6:
                description:
                    - IPv6 address of the local gateway.
            name:
                description:
                    - Tunnel name.
                required: true
            remote-gw:
                description:
                    - IP address of the remote gateway.
            remote-gw6:
                description:
                    - IPv6 address of the remote gateway.
            sequence-number-reception:
                description:
                    - Enable/disable validating sequence numbers in received GRE packets.
                choices:
                    - disable
                    - enable
            sequence-number-transmission:
                description:
                    - Enable/disable including of sequence numbers in transmitted GRE packets.
                choices:
                    - disable
                    - enable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure GRE tunnel.
    fortios_system_gre_tunnel:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_gre_tunnel:
        state: "present"
        checksum-reception: "disable"
        checksum-transmission: "disable"
        dscp-copying: "disable"
        interface: "<your_own_value> (source system.interface.name)"
        ip-version: "4"
        keepalive-failtimes: "8"
        keepalive-interval: "9"
        key-inbound: "10"
        key-outbound: "11"
        local-gw: "<your_own_value>"
        local-gw6: "<your_own_value>"
        name: "default_name_14"
        remote-gw: "<your_own_value>"
        remote-gw6: "<your_own_value>"
        sequence-number-reception: "disable"
        sequence-number-transmission: "disable"
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


def filter_system_gre_tunnel_data(json):
    option_list = ['checksum-reception', 'checksum-transmission', 'dscp-copying',
                   'interface', 'ip-version', 'keepalive-failtimes',
                   'keepalive-interval', 'key-inbound', 'key-outbound',
                   'local-gw', 'local-gw6', 'name',
                   'remote-gw', 'remote-gw6', 'sequence-number-reception',
                   'sequence-number-transmission']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_gre_tunnel(data, fos):
    vdom = data['vdom']
    system_gre_tunnel_data = data['system_gre_tunnel']
    filtered_data = filter_system_gre_tunnel_data(system_gre_tunnel_data)
    if system_gre_tunnel_data['state'] == "present":
        return fos.set('system',
                       'gre-tunnel',
                       data=filtered_data,
                       vdom=vdom)

    elif system_gre_tunnel_data['state'] == "absent":
        return fos.delete('system',
                          'gre-tunnel',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    methodlist = ['system_gre_tunnel']
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
        "https": {"required": False, "type": "bool", "default": True},
        "system_gre_tunnel": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "checksum-reception": {"required": False, "type": "str",
                                       "choices": ["disable", "enable"]},
                "checksum-transmission": {"required": False, "type": "str",
                                          "choices": ["disable", "enable"]},
                "dscp-copying": {"required": False, "type": "str",
                                 "choices": ["disable", "enable"]},
                "interface": {"required": False, "type": "str"},
                "ip-version": {"required": False, "type": "str",
                               "choices": ["4", "6"]},
                "keepalive-failtimes": {"required": False, "type": "int"},
                "keepalive-interval": {"required": False, "type": "int"},
                "key-inbound": {"required": False, "type": "int"},
                "key-outbound": {"required": False, "type": "int"},
                "local-gw": {"required": False, "type": "str"},
                "local-gw6": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "remote-gw": {"required": False, "type": "str"},
                "remote-gw6": {"required": False, "type": "str"},
                "sequence-number-reception": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                "sequence-number-transmission": {"required": False, "type": "str",
                                                 "choices": ["disable", "enable"]}

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
