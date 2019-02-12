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
module: fortios_system_mobile_tunnel
short_description: Configure Mobile tunnels, an implementation of Network Mobility (NEMO) extensions for Mobile IPv4 RFC5177 in Fortinet's FortiOS and
   FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system feature and mobile_tunnel category.
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
    system_mobile_tunnel:
        description:
            - Configure Mobile tunnels, an implementation of Network Mobility (NEMO) extensions for Mobile IPv4 RFC5177.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            hash-algorithm:
                description:
                    - Hash Algorithm (Keyed MD5).
                choices:
                    - hmac-md5
            home-address:
                description:
                    - "Home IP address (Format: xxx.xxx.xxx.xxx)."
            home-agent:
                description:
                    - "IPv4 address of the NEMO HA (Format: xxx.xxx.xxx.xxx)."
            lifetime:
                description:
                    - NMMO HA registration request lifetime (180 - 65535 sec, default = 65535).
            n-mhae-key:
                description:
                    - NEMO authentication key.
            n-mhae-key-type:
                description:
                    - NEMO authentication key type (ascii or base64).
                choices:
                    - ascii
                    - base64
            n-mhae-spi:
                description:
                    - "NEMO authentication SPI (default: 256)."
            name:
                description:
                    - Tunnel name.
                required: true
            network:
                description:
                    - NEMO network configuration.
                suboptions:
                    id:
                        description:
                            - Network entry ID.
                        required: true
                    interface:
                        description:
                            - Select the associated interface name from available options. Source system.interface.name.
                    prefix:
                        description:
                            - "Class IP and Netmask with correction (Format:xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx or xxx.xxx.xxx.xxx/x)."
            reg-interval:
                description:
                    - NMMO HA registration interval (5 - 300, default = 5).
            reg-retry:
                description:
                    - Maximum number of NMMO HA registration retries (1 to 30, default = 3).
            renew-interval:
                description:
                    - Time before lifetime expiraton to send NMMO HA re-registration (5 - 60, default = 60).
            roaming-interface:
                description:
                    - Select the associated interface name from available options. Source system.interface.name.
            status:
                description:
                    - Enable/disable this mobile tunnel.
                choices:
                    - disable
                    - enable
            tunnel-mode:
                description:
                    - NEMO tunnnel mode (GRE tunnel).
                choices:
                    - gre
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure Mobile tunnels, an implementation of Network Mobility (NEMO) extensions for Mobile IPv4 RFC5177.
    fortios_system_mobile_tunnel:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_mobile_tunnel:
        state: "present"
        hash-algorithm: "hmac-md5"
        home-address: "<your_own_value>"
        home-agent: "<your_own_value>"
        lifetime: "6"
        n-mhae-key: "<your_own_value>"
        n-mhae-key-type: "ascii"
        n-mhae-spi: "9"
        name: "default_name_10"
        network:
         -
            id:  "12"
            interface: "<your_own_value> (source system.interface.name)"
            prefix: "<your_own_value>"
        reg-interval: "15"
        reg-retry: "16"
        renew-interval: "17"
        roaming-interface: "<your_own_value> (source system.interface.name)"
        status: "disable"
        tunnel-mode: "gre"
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


def filter_system_mobile_tunnel_data(json):
    option_list = ['hash-algorithm', 'home-address', 'home-agent',
                   'lifetime', 'n-mhae-key', 'n-mhae-key-type',
                   'n-mhae-spi', 'name', 'network',
                   'reg-interval', 'reg-retry', 'renew-interval',
                   'roaming-interface', 'status', 'tunnel-mode']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_mobile_tunnel(data, fos):
    vdom = data['vdom']
    system_mobile_tunnel_data = data['system_mobile_tunnel']
    filtered_data = filter_system_mobile_tunnel_data(system_mobile_tunnel_data)
    if system_mobile_tunnel_data['state'] == "present":
        return fos.set('system',
                       'mobile-tunnel',
                       data=filtered_data,
                       vdom=vdom)

    elif system_mobile_tunnel_data['state'] == "absent":
        return fos.delete('system',
                          'mobile-tunnel',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    methodlist = ['system_mobile_tunnel']
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
        "system_mobile_tunnel": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "hash-algorithm": {"required": False, "type": "str",
                                   "choices": ["hmac-md5"]},
                "home-address": {"required": False, "type": "str"},
                "home-agent": {"required": False, "type": "str"},
                "lifetime": {"required": False, "type": "int"},
                "n-mhae-key": {"required": False, "type": "str"},
                "n-mhae-key-type": {"required": False, "type": "str",
                                    "choices": ["ascii", "base64"]},
                "n-mhae-spi": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "network": {"required": False, "type": "list",
                            "options": {
                                "id": {"required": True, "type": "int"},
                                "interface": {"required": False, "type": "str"},
                                "prefix": {"required": False, "type": "str"}
                            }},
                "reg-interval": {"required": False, "type": "int"},
                "reg-retry": {"required": False, "type": "int"},
                "renew-interval": {"required": False, "type": "int"},
                "roaming-interface": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["disable", "enable"]},
                "tunnel-mode": {"required": False, "type": "str",
                                "choices": ["gre"]}

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
