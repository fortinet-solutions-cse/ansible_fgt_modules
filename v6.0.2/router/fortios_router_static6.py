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
module: fortios_router_static6
short_description: Configure IPv6 static routing tables in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure router feature and static6 category.
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
    router_static6:
        description:
            - Configure IPv6 static routing tables.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            bfd:
                description:
                    - Enable/disable Bidirectional Forwarding Detection (BFD).
                choices:
                    - enable
                    - disable
            blackhole:
                description:
                    - Enable/disable black hole.
                choices:
                    - enable
                    - disable
            comment:
                description:
                    - Optional comments.
            device:
                description:
                    - Gateway out interface or tunnel. Source system.interface.name.
            devindex:
                description:
                    - Device index (0 - 4294967295).
            distance:
                description:
                    - Administrative distance (1 - 255).
            dst:
                description:
                    - Destination IPv6 prefix.
            gateway:
                description:
                    - IPv6 address of the gateway.
            priority:
                description:
                    - Administrative priority (0 - 4294967295).
            seq-num:
                description:
                    - Sequence number.
                required: true
            status:
                description:
                    - Enable/disable this static route.
                choices:
                    - enable
                    - disable
            virtual-wan-link:
                description:
                    - Enable/disable egress through the virtual-wan-link.
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
  tasks:
  - name: Configure IPv6 static routing tables.
    fortios_router_static6:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      router_static6:
        state: "present"
        bfd: "enable"
        blackhole: "enable"
        comment: "Optional comments."
        device: "<your_own_value> (source system.interface.name)"
        devindex: "7"
        distance: "8"
        dst: "<your_own_value>"
        gateway: "<your_own_value>"
        priority: "11"
        seq-num: "12"
        status: "enable"
        virtual-wan-link: "enable"
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


def filter_router_static6_data(json):
    option_list = ['bfd', 'blackhole', 'comment',
                   'device', 'devindex', 'distance',
                   'dst', 'gateway', 'priority',
                   'seq-num', 'status', 'virtual-wan-link']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def router_static6(data, fos):
    vdom = data['vdom']
    router_static6_data = data['router_static6']
    filtered_data = filter_router_static6_data(router_static6_data)
    if router_static6_data['state'] == "present":
        return fos.set('router',
                       'static6',
                       data=filtered_data,
                       vdom=vdom)

    elif router_static6_data['state'] == "absent":
        return fos.delete('router',
                          'static6',
                          mkey=filtered_data['seq-num'],
                          vdom=vdom)


def fortios_router(data, fos):
    login(data)

    methodlist = ['router_static6']
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
        "router_static6": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "bfd": {"required": False, "type": "str",
                        "choices": ["enable", "disable"]},
                "blackhole": {"required": False, "type": "str",
                              "choices": ["enable", "disable"]},
                "comment": {"required": False, "type": "str"},
                "device": {"required": False, "type": "str"},
                "devindex": {"required": False, "type": "int"},
                "distance": {"required": False, "type": "int"},
                "dst": {"required": False, "type": "str"},
                "gateway": {"required": False, "type": "str"},
                "priority": {"required": False, "type": "int"},
                "seq-num": {"required": True, "type": "int"},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "virtual-wan-link": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]}

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

    is_error, has_changed, result = fortios_router(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
