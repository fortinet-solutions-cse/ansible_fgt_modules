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
module: fortios_wireless_controller_hotspot20_anqp_ip_address_type
short_description: Configure IP address type availability in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify wireless_controller_hotspot20 feature and anqp_ip_address_type category.
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
    wireless_controller_hotspot20_anqp_ip_address_type:
        description:
            - Configure IP address type availability.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            ipv4-address-type:
                description:
                    - IPv4 address type.
                choices:
                    - not-available
                    - public
                    - port-restricted
                    - single-NATed-private
                    - double-NATed-private
                    - port-restricted-and-single-NATed
                    - port-restricted-and-double-NATed
                    - not-known
            ipv6-address-type:
                description:
                    - IPv6 address type.
                choices:
                    - not-available
                    - available
                    - not-known
            name:
                description:
                    - IP type name.
                required: true
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure IP address type availability.
    fortios_wireless_controller_hotspot20_anqp_ip_address_type:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wireless_controller_hotspot20_anqp_ip_address_type:
        state: "present"
        ipv4-address-type: "not-available"
        ipv6-address-type: "not-available"
        name: "default_name_5"
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


def filter_wireless_controller_hotspot20_anqp_ip_address_type_data(json):
    option_list = ['ipv4-address-type', 'ipv6-address-type', 'name']
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


def wireless_controller_hotspot20_anqp_ip_address_type(data, fos):
    vdom = data['vdom']
    wireless_controller_hotspot20_anqp_ip_address_type_data = data['wireless_controller_hotspot20_anqp_ip_address_type']
    flattened_data = flatten_multilists_attributes(wireless_controller_hotspot20_anqp_ip_address_type_data)
    filtered_data = filter_wireless_controller_hotspot20_anqp_ip_address_type_data(flattened_data)
    if wireless_controller_hotspot20_anqp_ip_address_type_data['state'] == "present":
        return fos.set('wireless-controller.hotspot20',
                       'anqp-ip-address-type',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller_hotspot20_anqp_ip_address_type_data['state'] == "absent":
        return fos.delete('wireless-controller.hotspot20',
                          'anqp-ip-address-type',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller_hotspot20(data, fos):
    login(data)

    methodlist = ['wireless_controller_hotspot20_anqp_ip_address_type']
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
        "wireless_controller_hotspot20_anqp_ip_address_type": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "ipv4-address-type": {"required": False, "type": "str",
                                      "choices": ["not-available", "public", "port-restricted",
                                                  "single-NATed-private", "double-NATed-private", "port-restricted-and-single-NATed",
                                                  "port-restricted-and-double-NATed", "not-known"]},
                "ipv6-address-type": {"required": False, "type": "str",
                                      "choices": ["not-available", "available", "not-known"]},
                "name": {"required": True, "type": "str"}

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

    is_error, has_changed, result = fortios_wireless_controller_hotspot20(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
