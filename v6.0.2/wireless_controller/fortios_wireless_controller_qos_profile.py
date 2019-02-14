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
module: fortios_wireless_controller_qos_profile
short_description: Configure WiFi quality of service (QoS) profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify wireless_controller feature and qos_profile category.
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
    wireless_controller_qos_profile:
        description:
            - Configure WiFi quality of service (QoS) profiles.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            bandwidth-admission-control:
                description:
                    - Enable/disable WMM bandwidth admission control.
                choices:
                    - enable
                    - disable
            bandwidth-capacity:
                description:
                    - Maximum bandwidth capacity allowed (1 - 600000 Kbps, default = 2000).
            burst:
                description:
                    - Enable/disable client rate burst.
                choices:
                    - enable
                    - disable
            call-admission-control:
                description:
                    - Enable/disable WMM call admission control.
                choices:
                    - enable
                    - disable
            call-capacity:
                description:
                    - Maximum number of Voice over WLAN (VoWLAN) phones allowed (0 - 60, default = 10).
            comment:
                description:
                    - Comment.
            downlink:
                description:
                    - Maximum downlink bandwidth for Virtual Access Points (VAPs) (0 - 2097152 Kbps, default = 0, 0 means no limit).
            downlink-sta:
                description:
                    - Maximum downlink bandwidth for clients (0 - 2097152 Kbps, default = 0, 0 means no limit).
            dscp-wmm-be:
                description:
                    - DSCP mapping for best effort access (default = 0 24).
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
            dscp-wmm-bk:
                description:
                    - DSCP mapping for background access (default = 8 16).
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
            dscp-wmm-mapping:
                description:
                    - Enable/disable Differentiated Services Code Point (DSCP) mapping.
                choices:
                    - enable
                    - disable
            dscp-wmm-vi:
                description:
                    - DSCP mapping for video access (default = 32 40).
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
            dscp-wmm-vo:
                description:
                    - DSCP mapping for voice access (default = 48 56).
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
            name:
                description:
                    - WiFi QoS profile name.
                required: true
            uplink:
                description:
                    - Maximum uplink bandwidth for Virtual Access Points (VAPs) (0 - 2097152 Kbps, default = 0, 0 means no limit).
            uplink-sta:
                description:
                    - Maximum uplink bandwidth for clients (0 - 2097152 Kbps, default = 0, 0 means no limit).
            wmm:
                description:
                    - Enable/disable WiFi multi-media (WMM) control.
                choices:
                    - enable
                    - disable
            wmm-uapsd:
                description:
                    - Enable/disable WMM Unscheduled Automatic Power Save Delivery (U-APSD) power save mode.
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
  - name: Configure WiFi quality of service (QoS) profiles.
    fortios_wireless_controller_qos_profile:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wireless_controller_qos_profile:
        state: "present"
        bandwidth-admission-control: "enable"
        bandwidth-capacity: "4"
        burst: "enable"
        call-admission-control: "enable"
        call-capacity: "7"
        comment: "Comment."
        downlink: "9"
        downlink-sta: "10"
        dscp-wmm-be:
         -
            id:  "12"
        dscp-wmm-bk:
         -
            id:  "14"
        dscp-wmm-mapping: "enable"
        dscp-wmm-vi:
         -
            id:  "17"
        dscp-wmm-vo:
         -
            id:  "19"
        name: "default_name_20"
        uplink: "21"
        uplink-sta: "22"
        wmm: "enable"
        wmm-uapsd: "enable"
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


def filter_wireless_controller_qos_profile_data(json):
    option_list = ['bandwidth-admission-control', 'bandwidth-capacity', 'burst',
                   'call-admission-control', 'call-capacity', 'comment',
                   'downlink', 'downlink-sta', 'dscp-wmm-be',
                   'dscp-wmm-bk', 'dscp-wmm-mapping', 'dscp-wmm-vi',
                   'dscp-wmm-vo', 'name', 'uplink',
                   'uplink-sta', 'wmm', 'wmm-uapsd']
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


def wireless_controller_qos_profile(data, fos):
    vdom = data['vdom']
    wireless_controller_qos_profile_data = data['wireless_controller_qos_profile']
    flattened_data = flatten_multilists_attributes(wireless_controller_qos_profile_data)
    filtered_data = filter_wireless_controller_qos_profile_data(flattened_data)
    if wireless_controller_qos_profile_data['state'] == "present":
        return fos.set('wireless-controller',
                       'qos-profile',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller_qos_profile_data['state'] == "absent":
        return fos.delete('wireless-controller',
                          'qos-profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller(data, fos):
    login(data)

    if data['wireless_controller_qos_profile']:
        resp = wireless_controller_qos_profile(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "wireless_controller_qos_profile": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "bandwidth-admission-control": {"required": False, "type": "str",
                                                "choices": ["enable", "disable"]},
                "bandwidth-capacity": {"required": False, "type": "int"},
                "burst": {"required": False, "type": "str",
                          "choices": ["enable", "disable"]},
                "call-admission-control": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "call-capacity": {"required": False, "type": "int"},
                "comment": {"required": False, "type": "str"},
                "downlink": {"required": False, "type": "int"},
                "downlink-sta": {"required": False, "type": "int"},
                "dscp-wmm-be": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "dscp-wmm-bk": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "dscp-wmm-mapping": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "dscp-wmm-vi": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "dscp-wmm-vo": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "name": {"required": True, "type": "str"},
                "uplink": {"required": False, "type": "int"},
                "uplink-sta": {"required": False, "type": "int"},
                "wmm": {"required": False, "type": "str",
                        "choices": ["enable", "disable"]},
                "wmm-uapsd": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_wireless_controller(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
