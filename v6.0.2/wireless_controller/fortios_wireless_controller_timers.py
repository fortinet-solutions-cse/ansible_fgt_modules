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
module: fortios_wireless_controller_timers
short_description: Configure CAPWAP timers in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify wireless_controller feature and timers category.
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
    wireless_controller_timers:
        description:
            - Configure CAPWAP timers.
        default: null
        suboptions:
            ble-scan-report-intv:
                description:
                    - Time between running Bluetooth Low Energy (BLE) reports (10 - 3600 sec, default = 30).
            client-idle-timeout:
                description:
                    - Time after which a client is considered idle and times out (20 - 3600 sec, default = 300, 0 for no timeout).
            darrp-day:
                description:
                    - Weekday on which to run DARRP optimization.
                choices:
                    - sunday
                    - monday
                    - tuesday
                    - wednesday
                    - thursday
                    - friday
                    - saturday
            darrp-optimize:
                description:
                    - Time for running Dynamic Automatic Radio Resource Provisioning (DARRP) optimizations (0 - 86400 sec, default = 1800).
            darrp-time:
                description:
                    - Time at which DARRP optimizations run (you can add up to 8 times).
                suboptions:
                    time:
                        description:
                            - Time.
                        required: true
            discovery-interval:
                description:
                    - Time between discovery requests (2 - 180 sec, default = 5).
            echo-interval:
                description:
                    - Time between echo requests sent by the managed WTP, AP, or FortiAP (1 - 255 sec, default = 30).
            fake-ap-log:
                description:
                    - Time between recording logs about fake APs if periodic fake AP logging is configured (0 - 1440 min, default = 1).
            ipsec-intf-cleanup:
                description:
                    - Time period to keep IPsec VPN interfaces up after WTP sessions are disconnected (30 - 3600 sec, default = 120).
            radio-stats-interval:
                description:
                    - Time between running radio reports (1 - 255 sec, default = 15).
            rogue-ap-log:
                description:
                    - Time between logging rogue AP messages if periodic rogue AP logging is configured (0 - 1440 min, default = 0).
            sta-capability-interval:
                description:
                    - Time between running station capability reports (1 - 255 sec, default = 30).
            sta-locate-timer:
                description:
                    - Time between running client presence flushes to remove clients that are listed but no longer present (0 - 86400 sec, default = 1800).
            sta-stats-interval:
                description:
                    - Time between running client (station) reports (1 - 255 sec, default = 1).
            vap-stats-interval:
                description:
                    - Time between running Virtual Access Point (VAP) reports (1 - 255 sec, default = 15).
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure CAPWAP timers.
    fortios_wireless_controller_timers:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wireless_controller_timers:
        ble-scan-report-intv: "3"
        client-idle-timeout: "4"
        darrp-day: "sunday"
        darrp-optimize: "6"
        darrp-time:
         -
            time: "<your_own_value>"
        discovery-interval: "9"
        echo-interval: "10"
        fake-ap-log: "11"
        ipsec-intf-cleanup: "12"
        radio-stats-interval: "13"
        rogue-ap-log: "14"
        sta-capability-interval: "15"
        sta-locate-timer: "16"
        sta-stats-interval: "17"
        vap-stats-interval: "18"
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


def filter_wireless_controller_timers_data(json):
    option_list = ['ble-scan-report-intv', 'client-idle-timeout', 'darrp-day',
                   'darrp-optimize', 'darrp-time', 'discovery-interval',
                   'echo-interval', 'fake-ap-log', 'ipsec-intf-cleanup',
                   'radio-stats-interval', 'rogue-ap-log', 'sta-capability-interval',
                   'sta-locate-timer', 'sta-stats-interval', 'vap-stats-interval']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def wireless_controller_timers(data, fos):
    vdom = data['vdom']
    wireless_controller_timers_data = data['wireless_controller_timers']
    filtered_data = filter_wireless_controller_timers_data(wireless_controller_timers_data)

    return fos.set('wireless-controller',
                   'timers',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_wireless_controller(data, fos):
    login(data, fos)

    if data['wireless_controller_timers']:
        resp = wireless_controller_timers(data, fos)

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
        "wireless_controller_timers": {
            "required": False, "type": "dict",
            "options": {
                "ble-scan-report-intv": {"required": False, "type": "int"},
                "client-idle-timeout": {"required": False, "type": "int"},
                "darrp-day": {"required": False, "type": "str",
                              "choices": ["sunday", "monday", "tuesday",
                                          "wednesday", "thursday", "friday",
                                          "saturday"]},
                "darrp-optimize": {"required": False, "type": "int"},
                "darrp-time": {"required": False, "type": "list",
                               "options": {
                                   "time": {"required": True, "type": "str"}
                               }},
                "discovery-interval": {"required": False, "type": "int"},
                "echo-interval": {"required": False, "type": "int"},
                "fake-ap-log": {"required": False, "type": "int"},
                "ipsec-intf-cleanup": {"required": False, "type": "int"},
                "radio-stats-interval": {"required": False, "type": "int"},
                "rogue-ap-log": {"required": False, "type": "int"},
                "sta-capability-interval": {"required": False, "type": "int"},
                "sta-locate-timer": {"required": False, "type": "int"},
                "sta-stats-interval": {"required": False, "type": "int"},
                "vap-stats-interval": {"required": False, "type": "int"}

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

    is_error, has_changed, result = fortios_wireless_controller(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
