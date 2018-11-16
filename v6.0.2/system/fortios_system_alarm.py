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
module: fortios_system_alarm
short_description: Configure alarm.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system feature and alarm category.
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
    system_alarm:
        description:
            - Configure alarm.
        default: null
        suboptions:
            audible:
                description:
                    - Enable/disable audible alarm.
                choices:
                    - enable
                    - disable
            groups:
                description:
                    - Alarm groups.
                suboptions:
                    admin-auth-failure-threshold:
                        description:
                            - Admin authentication failure threshold.
                    admin-auth-lockout-threshold:
                        description:
                            - Admin authentication lockout threshold.
                    decryption-failure-threshold:
                        description:
                            - Decryption failure threshold.
                    encryption-failure-threshold:
                        description:
                            - Encryption failure threshold.
                    fw-policy-id:
                        description:
                            - Firewall policy ID.
                    fw-policy-id-threshold:
                        description:
                            - Firewall policy ID threshold.
                    fw-policy-violations:
                        description:
                            - Firewall policy violations.
                        suboptions:
                            dst-ip:
                                description:
                                    - Destination IP (0=all).
                            dst-port:
                                description:
                                    - Destination port (0=all).
                            id:
                                description:
                                    - Firewall policy violations ID.
                                required: true
                            src-ip:
                                description:
                                    - Source IP (0=all).
                            src-port:
                                description:
                                    - Source port (0=all).
                            threshold:
                                description:
                                    - Firewall policy violation threshold.
                    id:
                        description:
                            - Group ID.
                        required: true
                    log-full-warning-threshold:
                        description:
                            - Log full warning threshold.
                    period:
                        description:
                            - Time period in seconds (0 = from start up).
                    replay-attempt-threshold:
                        description:
                            - Replay attempt threshold.
                    self-test-failure-threshold:
                        description:
                            - Self-test failure threshold.
                    user-auth-failure-threshold:
                        description:
                            - User authentication failure threshold.
                    user-auth-lockout-threshold:
                        description:
                            - User authentication lockout threshold.
            status:
                description:
                    - Enable/disable alarm.
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
  - name: Configure alarm.
    fortios_system_alarm:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      system_alarm:
        audible: "enable"
        groups:
         -
            admin-auth-failure-threshold: "5"
            admin-auth-lockout-threshold: "6"
            decryption-failure-threshold: "7"
            encryption-failure-threshold: "8"
            fw-policy-id: "9"
            fw-policy-id-threshold: "10"
            fw-policy-violations:
             -
                dst-ip: "<your_own_value>"
                dst-port: "13"
                id:  "14"
                src-ip: "<your_own_value>"
                src-port: "16"
                threshold: "17"
            id:  "18"
            log-full-warning-threshold: "19"
            period: "20"
            replay-attempt-threshold: "21"
            self-test-failure-threshold: "22"
            user-auth-failure-threshold: "23"
            user-auth-lockout-threshold: "24"
        status: "enable"
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


def filter_system_alarm_data(json):
    option_list = ['audible', 'groups', 'status']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_alarm(data, fos):
    vdom = data['vdom']
    system_alarm_data = data['system_alarm']
    filtered_data = filter_system_alarm_data(system_alarm_data)
    return fos.set('system',
                   'alarm',
                   data=filtered_data,
                   vdom=vdom)


def fortios_system(data, fos):
    login(data)

    methodlist = ['system_alarm']
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
        "system_alarm": {
            "required": False, "type": "dict",
            "options": {
                "audible": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]},
                "groups": {"required": False, "type": "list",
                           "options": {
                               "admin-auth-failure-threshold": {"required": False, "type": "int"},
                               "admin-auth-lockout-threshold": {"required": False, "type": "int"},
                               "decryption-failure-threshold": {"required": False, "type": "int"},
                               "encryption-failure-threshold": {"required": False, "type": "int"},
                               "fw-policy-id": {"required": False, "type": "int"},
                               "fw-policy-id-threshold": {"required": False, "type": "int"},
                               "fw-policy-violations": {"required": False, "type": "list",
                                                        "options": {
                                                            "dst-ip": {"required": False, "type": "str"},
                                                            "dst-port": {"required": False, "type": "int"},
                                                            "id": {"required": True, "type": "int"},
                                                            "src-ip": {"required": False, "type": "str"},
                                                            "src-port": {"required": False, "type": "int"},
                                                            "threshold": {"required": False, "type": "int"}
                                                        }},
                               "id": {"required": True, "type": "int"},
                               "log-full-warning-threshold": {"required": False, "type": "int"},
                               "period": {"required": False, "type": "int"},
                               "replay-attempt-threshold": {"required": False, "type": "int"},
                               "self-test-failure-threshold": {"required": False, "type": "int"},
                               "user-auth-failure-threshold": {"required": False, "type": "int"},
                               "user-auth-lockout-threshold": {"required": False, "type": "int"}
                           }},
                "status": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
