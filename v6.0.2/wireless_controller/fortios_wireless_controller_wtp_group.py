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
module: fortios_wireless_controller_wtp_group
short_description: Configure WTP groups in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wireless_controller feature and wtp_group category.
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
    wireless_controller_wtp_group:
        description:
            - Configure WTP groups.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            name:
                description:
                    - WTP group name.
                required: true
            platform-type:
                description:
                    - FortiAP models to define the WTP group platform type.
                choices:
                    - AP-11N
                    - 220B
                    - 210B
                    - 222B
                    - 112B
                    - 320B
                    - 11C
                    - 14C
                    - 223B
                    - 28C
                    - 320C
                    - 221C
                    - 25D
                    - 222C
                    - 224D
                    - 214B
                    - 21D
                    - 24D
                    - 112D
                    - 223C
                    - 321C
                    - C220C
                    - C225C
                    - C23JD
                    - C24JE
                    - S321C
                    - S322C
                    - S323C
                    - S311C
                    - S313C
                    - S321CR
                    - S322CR
                    - S323CR
                    - S421E
                    - S422E
                    - S423E
                    - 421E
                    - 423E
                    - 221E
                    - 222E
                    - 223E
                    - 224E
                    - S221E
                    - S223E
                    - U421E
                    - U422EV
                    - U423E
                    - U221EV
                    - U223EV
                    - U24JEV
                    - U321EV
                    - U323EV
            wtps:
                description:
                    - WTP list.
                suboptions:
                    wtp-id:
                        description:
                            - WTP ID. Source wireless-controller.wtp.wtp-id.
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
  - name: Configure WTP groups.
    fortios_wireless_controller_wtp_group:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wireless_controller_wtp_group:
        state: "present"
        name: "default_name_3"
        platform-type: "AP-11N"
        wtps:
         -
            wtp-id: "<your_own_value> (source wireless-controller.wtp.wtp-id)"
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


def filter_wireless_controller_wtp_group_data(json):
    option_list = ['name', 'platform-type', 'wtps']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def wireless_controller_wtp_group(data, fos):
    vdom = data['vdom']
    wireless_controller_wtp_group_data = data['wireless_controller_wtp_group']
    filtered_data = filter_wireless_controller_wtp_group_data(wireless_controller_wtp_group_data)
    if wireless_controller_wtp_group_data['state'] == "present":
        return fos.set('wireless-controller',
                       'wtp-group',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller_wtp_group_data['state'] == "absent":
        return fos.delete('wireless-controller',
                          'wtp-group',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller(data, fos):
    login(data)

    methodlist = ['wireless_controller_wtp_group']
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
        "wireless_controller_wtp_group": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "name": {"required": True, "type": "str"},
                "platform-type": {"required": False, "type": "str",
                                  "choices": ["AP-11N", "220B", "210B",
                                              "222B", "112B", "320B",
                                              "11C", "14C", "223B",
                                              "28C", "320C", "221C",
                                              "25D", "222C", "224D",
                                              "214B", "21D", "24D",
                                              "112D", "223C", "321C",
                                              "C220C", "C225C", "C23JD",
                                              "C24JE", "S321C", "S322C",
                                              "S323C", "S311C", "S313C",
                                              "S321CR", "S322CR", "S323CR",
                                              "S421E", "S422E", "S423E",
                                              "421E", "423E", "221E",
                                              "222E", "223E", "224E",
                                              "S221E", "S223E", "U421E",
                                              "U422EV", "U423E", "U221EV",
                                              "U223EV", "U24JEV", "U321EV",
                                              "U323EV"]},
                "wtps": {"required": False, "type": "list",
                         "options": {
                             "wtp-id": {"required": True, "type": "str"}
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

    is_error, has_changed, result = fortios_wireless_controller(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
