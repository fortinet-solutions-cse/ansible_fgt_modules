#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
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
module: fortios_wanopt_cache_service
short_description: Designate cache-service for wan-optimization and webcache.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wanopt feature and cache_service category.
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
        default: false
    wanopt_cache_service:
        description:
            - Designate cache-service for wan-optimization and webcache.
        default: null
        suboptions:
            acceptable-connections:
                description:
                    - Set strategy when accepting cache collaboration connection.
                choices:
                    - any
                    - peers
            collaboration:
                description:
                    - Enable/disable cache-collaboration between cache-service clusters.
                choices:
                    - enable
                    - disable
            device-id:
                description:
                    - Set identifier for this cache device.
            dst-peer:
                description:
                    - Modify cache-service destination peer list.
                suboptions:
                    auth-type:
                        description:
                            - Set authentication type for this peer.
                    device-id:
                        description:
                            - Device ID of this peer.
                        required: true
                    encode-type:
                        description:
                            - Set encode type for this peer.
                    ip:
                        description:
                            - Set cluster IP address of this peer.
                    priority:
                        description:
                            - Set priority for this peer.
            prefer-scenario:
                description:
                    - Set the preferred cache behavior towards the balance between latency and hit-ratio.
                choices:
                    - balance
                    - prefer-speed
                    - prefer-cache
            src-peer:
                description:
                    - Modify cache-service source peer list.
                suboptions:
                    auth-type:
                        description:
                            - Set authentication type for this peer.
                    device-id:
                        description:
                            - Device ID of this peer.
                        required: true
                    encode-type:
                        description:
                            - Set encode type for this peer.
                    ip:
                        description:
                            - Set cluster IP address of this peer.
                    priority:
                        description:
                            - Set priority for this peer.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Designate cache-service for wan-optimization and webcache.
    fortios_wanopt_cache_service:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      wanopt_cache_service:
        acceptable-connections: "any"
        collaboration: "enable"
        device-id: "<your_own_value>"
        dst-peer:
         -
            auth-type: "7"
            device-id: "<your_own_value>"
            encode-type: "9"
            ip: "<your_own_value>"
            priority: "11"
        prefer-scenario: "balance"
        src-peer:
         -
            auth-type: "14"
            device-id: "<your_own_value>"
            encode-type: "16"
            ip: "<your_own_value>"
            priority: "18"
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


def filter_wanopt_cache_service_data(json):
    option_list = ['acceptable-connections', 'collaboration', 'device-id',
                   'dst-peer', 'prefer-scenario', 'src-peer']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def wanopt_cache_service(data, fos):
    vdom = data['vdom']
    wanopt_cache_service_data = data['wanopt_cache_service']
    filtered_data = filter_wanopt_cache_service_data(wanopt_cache_service_data)
    return fos.set('wanopt',
                   'cache-service',
                   data=filtered_data,
                   vdom=vdom)


def fortios_wanopt(data, fos):
    login(data)

    methodlist = ['wanopt_cache_service']
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
        "https": {"required": False, "type": "bool", "default": "False"},
        "wanopt_cache_service": {
            "required": False, "type": "dict",
            "options": {
                "acceptable-connections": {"required": False, "type": "str",
                                           "choices": ["any", "peers"]},
                "collaboration": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "device-id": {"required": False, "type": "str"},
                "dst-peer": {"required": False, "type": "list",
                             "options": {
                                 "auth-type": {"required": False, "type": "int"},
                                 "device-id": {"required": True, "type": "str"},
                                 "encode-type": {"required": False, "type": "int"},
                                 "ip": {"required": False, "type": "str"},
                                 "priority": {"required": False, "type": "int"}
                             }},
                "prefer-scenario": {"required": False, "type": "str",
                                    "choices": ["balance", "prefer-speed", "prefer-cache"]},
                "src-peer": {"required": False, "type": "list",
                             "options": {
                                 "auth-type": {"required": False, "type": "int"},
                                 "device-id": {"required": True, "type": "str"},
                                 "encode-type": {"required": False, "type": "int"},
                                 "ip": {"required": False, "type": "str"},
                                 "priority": {"required": False, "type": "int"}
                             }}

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

    is_error, has_changed, result = fortios_wanopt(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
