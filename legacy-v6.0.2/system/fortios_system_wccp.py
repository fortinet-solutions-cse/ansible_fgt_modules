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
module: fortios_system_wccp
short_description: Configure WCCP in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and wccp category.
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
    system_wccp:
        description:
            - Configure WCCP.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            assignment-bucket-format:
                description:
                    - Assignment bucket format for the WCCP cache engine.
                choices:
                    - wccp-v2
                    - cisco-implementation
            assignment-dstaddr-mask:
                description:
                    - Assignment destination address mask.
            assignment-method:
                description:
                    - Hash key assignment preference.
                choices:
                    - HASH
                    - MASK
                    - any
            assignment-srcaddr-mask:
                description:
                    - Assignment source address mask.
            assignment-weight:
                description:
                    - Assignment of hash weight/ratio for the WCCP cache engine.
            authentication:
                description:
                    - Enable/disable MD5 authentication.
                choices:
                    - enable
                    - disable
            cache-engine-method:
                description:
                    - Method used to forward traffic to the routers or to return to the cache engine.
                choices:
                    - GRE
                    - L2
            cache-id:
                description:
                    - IP address known to all routers. If the addresses are the same, use the default 0.0.0.0.
            forward-method:
                description:
                    - Method used to forward traffic to the cache servers.
                choices:
                    - GRE
                    - L2
                    - any
            group-address:
                description:
                    - IP multicast address used by the cache routers. For the FortiGate to ignore multicast WCCP traffic, use the default 0.0.0.0.
            password:
                description:
                    - Password for MD5 authentication.
            ports:
                description:
                    - Service ports.
            ports-defined:
                description:
                    - Match method.
                choices:
                    - source
                    - destination
            primary-hash:
                description:
                    - Hash method.
                choices:
                    - src-ip
                    - dst-ip
                    - src-port
                    - dst-port
            priority:
                description:
                    - Service priority.
            protocol:
                description:
                    - Service protocol.
            return-method:
                description:
                    -  Method used to decline a redirected packet and return it to the FortiGate.
                choices:
                    - GRE
                    - L2
                    - any
            router-id:
                description:
                    - IP address known to all cache engines. If all cache engines connect to the same FortiGate interface, use the default 0.0.0.0.
            router-list:
                description:
                    - IP addresses of one or more WCCP routers.
            server-list:
                description:
                    - IP addresses and netmasks for up to four cache servers.
            service-id:
                description:
                    - Service ID.
                required: true
            service-type:
                description:
                    - WCCP service type used by the cache server for logical interception and redirection of traffic.
                choices:
                    - auto
                    - standard
                    - dynamic
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure WCCP.
    fortios_system_wccp:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_wccp:
        state: "present"
        assignment-bucket-format: "wccp-v2"
        assignment-dstaddr-mask: "<your_own_value>"
        assignment-method: "HASH"
        assignment-srcaddr-mask: "<your_own_value>"
        assignment-weight: "7"
        authentication: "enable"
        cache-engine-method: "GRE"
        cache-id: "<your_own_value>"
        forward-method: "GRE"
        group-address: "<your_own_value>"
        password: "<your_own_value>"
        ports: "<your_own_value>"
        ports-defined: "source"
        primary-hash: "src-ip"
        priority: "17"
        protocol: "18"
        return-method: "GRE"
        router-id: "<your_own_value>"
        router-list: "<your_own_value>"
        server-list: "<your_own_value>"
        service-id: "<your_own_value>"
        service-type: "auto"
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


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password)


def filter_system_wccp_data(json):
    option_list = ['assignment-bucket-format', 'assignment-dstaddr-mask', 'assignment-method',
                   'assignment-srcaddr-mask', 'assignment-weight', 'authentication',
                   'cache-engine-method', 'cache-id', 'forward-method',
                   'group-address', 'password', 'ports',
                   'ports-defined', 'primary-hash', 'priority',
                   'protocol', 'return-method', 'router-id',
                   'router-list', 'server-list', 'service-id',
                   'service-type']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_wccp(data, fos):
    vdom = data['vdom']
    system_wccp_data = data['system_wccp']
    filtered_data = filter_system_wccp_data(system_wccp_data)

    if system_wccp_data['state'] == "present":
        return fos.set('system',
                       'wccp',
                       data=filtered_data,
                       vdom=vdom)

    elif system_wccp_data['state'] == "absent":
        return fos.delete('system',
                          'wccp',
                          mkey=filtered_data['service-id'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):
    login(data, fos)

    if data['system_wccp']:
        resp = system_wccp(data, fos)

    fos.logout()
    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_wccp": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "assignment-bucket-format": {"required": False, "type": "str",
                                             "choices": ["wccp-v2", "cisco-implementation"]},
                "assignment-dstaddr-mask": {"required": False, "type": "ipv4-netmask-any"},
                "assignment-method": {"required": False, "type": "str",
                                      "choices": ["HASH", "MASK", "any"]},
                "assignment-srcaddr-mask": {"required": False, "type": "ipv4-netmask-any"},
                "assignment-weight": {"required": False, "type": "int"},
                "authentication": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "cache-engine-method": {"required": False, "type": "str",
                                        "choices": ["GRE", "L2"]},
                "cache-id": {"required": False, "type": "str"},
                "forward-method": {"required": False, "type": "str",
                                   "choices": ["GRE", "L2", "any"]},
                "group-address": {"required": False, "type": "ipv4-address-multicast"},
                "password": {"required": False, "type": "str"},
                "ports": {"required": False, "type": "str"},
                "ports-defined": {"required": False, "type": "str",
                                  "choices": ["source", "destination"]},
                "primary-hash": {"required": False, "type": "str",
                                 "choices": ["src-ip", "dst-ip", "src-port",
                                             "dst-port"]},
                "priority": {"required": False, "type": "int"},
                "protocol": {"required": False, "type": "int"},
                "return-method": {"required": False, "type": "str",
                                  "choices": ["GRE", "L2", "any"]},
                "router-id": {"required": False, "type": "str"},
                "router-list": {"required": False, "type": "str"},
                "server-list": {"required": False, "type": "str"},
                "service-id": {"required": True, "type": "str"},
                "service-type": {"required": False, "type": "str",
                                 "choices": ["auto", "standard", "dynamic"]}

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
