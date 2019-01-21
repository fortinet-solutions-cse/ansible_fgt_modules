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
module: fortios_firewall_address6
short_description: Configure IPv6 firewall addresses in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure firewall feature and address6 category.
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
    firewall_address6:
        description:
            - Configure IPv6 firewall addresses.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            cache-ttl:
                description:
                    - Minimal TTL of individual IPv6 addresses in FQDN cache.
            color:
                description:
                    - Integer value to determine the color of the icon in the GUI (range 1 to 32, default = 0, which sets the value to 1).
            comment:
                description:
                    - Comment.
            end-ip:
                description:
                    - "Final IP address (inclusive) in the range for the address (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx)."
            fqdn:
                description:
                    - Fully qualified domain name.
            host:
                description:
                    - Host Address.
            host-type:
                description:
                    - Host type.
                choices:
                    - any
                    - specific
            ip6:
                description:
                    - "IPv6 address prefix (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx)."
            list:
                description:
                    - IP address list.
                suboptions:
                    ip:
                        description:
                            - IP.
                        required: true
            name:
                description:
                    - Address name.
                required: true
            obj-id:
                description:
                    - Object ID for NSX.
            sdn:
                description:
                    - SDN.
                choices:
                    - nsx
            start-ip:
                description:
                    - "First IP address (inclusive) in the range for the address (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx)."
            subnet-segment:
                description:
                    - IPv6 subnet segments.
                suboptions:
                    name:
                        description:
                            - Name.
                        required: true
                    type:
                        description:
                            - Subnet segment type.
                        choices:
                            - any
                            - specific
                    value:
                        description:
                            - Subnet segment value.
            tagging:
                description:
                    - Config object tagging
                suboptions:
                    category:
                        description:
                            - Tag category. Source system.object-tagging.category.
                    name:
                        description:
                            - Tagging entry name.
                        required: true
                    tags:
                        description:
                            - Tags.
                        suboptions:
                            name:
                                description:
                                    - Tag name. Source system.object-tagging.tags.name.
                                required: true
            template:
                description:
                    - IPv6 address template. Source firewall.address6-template.name.
            type:
                description:
                    - Type of IPv6 address object (default = ipprefix).
                choices:
                    - ipprefix
                    - iprange
                    - fqdn
                    - dynamic
                    - template
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
            visibility:
                description:
                    - Enable/disable the visibility of the object in the GUI.
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
  - name: Configure IPv6 firewall addresses.
    fortios_firewall_address6:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      firewall_address6:
        state: "present"
        cache-ttl: "3"
        color: "4"
        comment: "Comment."
        end-ip: "<your_own_value>"
        fqdn: "<your_own_value>"
        host: "<your_own_value>"
        host-type: "any"
        ip6: "<your_own_value>"
        list:
         -
            ip: "<your_own_value>"
        name: "default_name_13"
        obj-id: "<your_own_value>"
        sdn: "nsx"
        start-ip: "<your_own_value>"
        subnet-segment:
         -
            name: "default_name_18"
            type: "any"
            value: "<your_own_value>"
        tagging:
         -
            category: "<your_own_value> (source system.object-tagging.category)"
            name: "default_name_23"
            tags:
             -
                name: "default_name_25 (source system.object-tagging.tags.name)"
        template: "<your_own_value> (source firewall.address6-template.name)"
        type: "ipprefix"
        uuid: "<your_own_value>"
        visibility: "enable"
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


def filter_firewall_address6_data(json):
    option_list = ['cache-ttl', 'color', 'comment',
                   'end-ip', 'fqdn', 'host',
                   'host-type', 'ip6', 'list',
                   'name', 'obj-id', 'sdn',
                   'start-ip', 'subnet-segment', 'tagging',
                   'template', 'type', 'uuid',
                   'visibility']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def firewall_address6(data, fos):
    vdom = data['vdom']
    firewall_address6_data = data['firewall_address6']
    filtered_data = filter_firewall_address6_data(firewall_address6_data)
    if firewall_address6_data['state'] == "present":
        return fos.set('firewall',
                       'address6',
                       data=filtered_data,
                       vdom=vdom)

    elif firewall_address6_data['state'] == "absent":
        return fos.delete('firewall',
                          'address6',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_firewall(data, fos):
    login(data)

    methodlist = ['firewall_address6']
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
        "firewall_address6": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "cache-ttl": {"required": False, "type": "int"},
                "color": {"required": False, "type": "int"},
                "comment": {"required": False, "type": "str"},
                "end-ip": {"required": False, "type": "str"},
                "fqdn": {"required": False, "type": "str"},
                "host": {"required": False, "type": "str"},
                "host-type": {"required": False, "type": "str",
                              "choices": ["any", "specific"]},
                "ip6": {"required": False, "type": "str"},
                "list": {"required": False, "type": "list",
                         "options": {
                             "ip": {"required": True, "type": "str"}
                         }},
                "name": {"required": True, "type": "str"},
                "obj-id": {"required": False, "type": "str"},
                "sdn": {"required": False, "type": "str",
                        "choices": ["nsx"]},
                "start-ip": {"required": False, "type": "str"},
                "subnet-segment": {"required": False, "type": "list",
                                   "options": {
                                       "name": {"required": True, "type": "str"},
                                       "type": {"required": False, "type": "str",
                                                "choices": ["any", "specific"]},
                                       "value": {"required": False, "type": "str"}
                                   }},
                "tagging": {"required": False, "type": "list",
                            "options": {
                                "category": {"required": False, "type": "str"},
                                "name": {"required": True, "type": "str"},
                                "tags": {"required": False, "type": "list",
                                         "options": {
                                             "name": {"required": True, "type": "str"}
                                         }}
                            }},
                "template": {"required": False, "type": "str"},
                "type": {"required": False, "type": "str",
                         "choices": ["ipprefix", "iprange", "fqdn",
                                     "dynamic", "template"]},
                "uuid": {"required": False, "type": "str"},
                "visibility": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_firewall(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
