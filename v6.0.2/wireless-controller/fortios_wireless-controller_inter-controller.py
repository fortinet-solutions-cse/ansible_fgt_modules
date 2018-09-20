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
module: fortios_wireless-controller_inter-controller
short_description: Configure inter wireless controller operation.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wireless-controller feature and inter-controller category.
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
    wireless-controller_inter-controller:
        description:
            - Configure inter wireless controller operation.
        default: null
        suboptions:
            fast-failover-max:
                description:
                    - Maximum number of retransmissions for fast failover HA messages between peer wireless controllers (3 - 64, default = 10).
            fast-failover-wait:
                description:
                    - Minimum wait time before an AP transitions from secondary controller to primary controller (10 - 86400 sec, default = 10).
            inter-controller-key:
                description:
                    - Secret key for inter-controller communications.
            inter-controller-mode:
                description:
                    - Configure inter-controller mode (disable, l2-roaming, 1+1, default = disable).
                choices:
                    - disable
                    - l2-roaming
                    - 1+1
            inter-controller-peer:
                description:
                    - Fast failover peer wireless controller list.
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                    peer-ip:
                        description:
                            - Peer wireless controller's IP address.
                    peer-port:
                        description:
                            - Port used by the wireless controller's for inter-controller communications (1024 - 49150, default = 5246).
                    peer-priority:
                        description:
                            - Peer wireless controller's priority (primary or secondary, default = primary).
                        choices:
                            - primary
                            - secondary
            inter-controller-pri:
                description:
                    - Configure inter-controller's priority (primary or secondary, default = primary).
                choices:
                    - primary
                    - secondary
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure inter wireless controller operation.
    fortios_wireless-controller_inter-controller:
      host:  "{{  host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      wireless-controller_inter-controller:
        state: "present"
        fast-failover-max: "3"
        fast-failover-wait: "4"
        inter-controller-key: "<your_own_value>"
        inter-controller-mode: "disable"
        inter-controller-peer:
         -
            id:  "8"
            peer-ip: "<your_own_value>"
            peer-port: "10"
            peer-priority: "primary"
        inter-controller-pri: "primary"
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


def filter_wireless-controller_inter-controller_data(json):
    option_list = ['fast-failover-max', 'fast-failover-wait', 'inter-controller-key',
                   'inter-controller-mode', 'inter-controller-peer', 'inter-controller-pri']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def wireless-controller_inter-controller(data, fos):
    vdom = data['vdom']
    wireless-controller_inter-controller_data = data['wireless-controller_inter-controller']
    filtered_data = filter_wireless-controller_inter - \
        controller_data(wireless-controller_inter-controller_data)

    if wireless-controller_inter-controller_data['state'] == "present":
        return fos.set('wireless-controller',
                       'inter-controller',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless-controller_inter-controller_data['state'] == "absent":
        return fos.delete('wireless-controller',
                          'inter-controller',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_wireless-controller(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    fos.https('off')
    fos.login(host, username, password)

    methodlist = ['wireless-controller_inter-controller']
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
        "wireless-controller_inter-controller": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str"},
                "fast-failover-max": {"required": False, "type": "int"},
                "fast-failover-wait": {"required": False, "type": "int"},
                "inter-controller-key": {"required": False, "type": "password"},
                "inter-controller-mode": {"required": False, "type": "str",
                                          "choices": ["disable", "l2-roaming", "1+1"]},
                "inter-controller-peer": {"required": False, "type": "list",
                                          "options": {
                                              "id": {"required": True, "type": "int"},
                                              "peer-ip": {"required": False, "type": "ipv4-address"},
                                              "peer-port": {"required": False, "type": "int"},
                                              "peer-priority": {"required": False, "type": "str",
                                                                "choices": ["primary", "secondary"]}
                                          }},
                "inter-controller-pri": {"required": False, "type": "str",
                                         "choices": ["primary", "secondary"]}

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

    is_error, has_changed, result = fortios_wireless - \
        controller(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
