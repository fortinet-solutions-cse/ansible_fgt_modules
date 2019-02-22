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
module: fortios_wireless_controller_ble_profile
short_description: Configure Bluetooth Low Energy profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify wireless_controller feature and ble_profile category.
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
    wireless_controller_ble_profile:
        description:
            - Configure Bluetooth Low Energy profile.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            advertising:
                description:
                    - Advertising type.
                choices:
                    - ibeacon
                    - eddystone-uid
                    - eddystone-url
            beacon-interval:
                description:
                    - Beacon interval (default = 100 msec).
            ble-scanning:
                description:
                    - Enable/disable Bluetooth Low Energy (BLE) scanning.
                choices:
                    - enable
                    - disable
            comment:
                description:
                    - Comment.
            eddystone-instance:
                description:
                    - Eddystone instance ID.
            eddystone-namespace:
                description:
                    - Eddystone namespace ID.
            eddystone-url:
                description:
                    - Eddystone URL.
            eddystone-url-encode-hex:
                description:
                    - Eddystone encoded URL hexadecimal string
            ibeacon-uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
            major-id:
                description:
                    - Major ID.
            minor-id:
                description:
                    - Minor ID.
            name:
                description:
                    - Bluetooth Low Energy profile name.
                required: true
            txpower:
                description:
                    - Transmit power level (default = 0).
                choices:
                    - 0
                    - 1
                    - 2
                    - 3
                    - 4
                    - 5
                    - 6
                    - 7
                    - 8
                    - 9
                    - 10
                    - 11
                    - 12
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure Bluetooth Low Energy profile.
    fortios_wireless_controller_ble_profile:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wireless_controller_ble_profile:
        state: "present"
        advertising: "ibeacon"
        beacon-interval: "4"
        ble-scanning: "enable"
        comment: "Comment."
        eddystone-instance: "<your_own_value>"
        eddystone-namespace: "<your_own_value>"
        eddystone-url: "<your_own_value>"
        eddystone-url-encode-hex: "<your_own_value>"
        ibeacon-uuid: "<your_own_value>"
        major-id: "12"
        minor-id: "13"
        name: "default_name_14"
        txpower: "0"
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


def filter_wireless_controller_ble_profile_data(json):
    option_list = ['advertising', 'beacon-interval', 'ble-scanning',
                   'comment', 'eddystone-instance', 'eddystone-namespace',
                   'eddystone-url', 'eddystone-url-encode-hex', 'ibeacon-uuid',
                   'major-id', 'minor-id', 'name',
                   'txpower']
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


def wireless_controller_ble_profile(data, fos):
    vdom = data['vdom']
    wireless_controller_ble_profile_data = data['wireless_controller_ble_profile']
    flattened_data = flatten_multilists_attributes(wireless_controller_ble_profile_data)
    filtered_data = filter_wireless_controller_ble_profile_data(flattened_data)
    if wireless_controller_ble_profile_data['state'] == "present":
        return fos.set('wireless-controller',
                       'ble-profile',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller_ble_profile_data['state'] == "absent":
        return fos.delete('wireless-controller',
                          'ble-profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller(data, fos):
    login(data)

    if data['wireless_controller_ble_profile']:
        resp = wireless_controller_ble_profile(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "wireless_controller_ble_profile": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "advertising": {"required": False, "type": "str",
                                "choices": ["ibeacon", "eddystone-uid", "eddystone-url"]},
                "beacon-interval": {"required": False, "type": "int"},
                "ble-scanning": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "comment": {"required": False, "type": "str"},
                "eddystone-instance": {"required": False, "type": "str"},
                "eddystone-namespace": {"required": False, "type": "str"},
                "eddystone-url": {"required": False, "type": "str"},
                "eddystone-url-encode-hex": {"required": False, "type": "str"},
                "ibeacon-uuid": {"required": False, "type": "str"},
                "major-id": {"required": False, "type": "int"},
                "minor-id": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "txpower": {"required": False, "type": "str",
                            "choices": ["0", "1", "2",
                                        "3", "4", "5",
                                        "6", "7", "8",
                                        "9", "10", "11",
                                        "12"]}

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

    is_error, has_changed, result = fortios_wireless_controller(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
