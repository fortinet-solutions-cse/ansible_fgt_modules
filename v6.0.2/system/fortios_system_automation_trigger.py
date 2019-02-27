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
module: fortios_system_automation_trigger
short_description: Trigger for automation stitches in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and automation_trigger category.
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
    system_automation_trigger:
        description:
            - Trigger for automation stitches.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            event-type:
                description:
                    - Event type.
                choices:
                    - ioc
                    - event-log
                    - reboot
                    - low-memory
                    - high-cpu
                    - license-near-expiry
                    - ha-failover
                    - config-change
                    - security-rating-summary
                    - virus-ips-db-updated
            ioc-level:
                description:
                    - IOC threat level.
                choices:
                    - medium
                    - high
            license-type:
                description:
                    - License type.
                choices:
                    - forticare-support
                    - fortiguard-webfilter
                    - fortiguard-antispam
                    - fortiguard-antivirus
                    - fortiguard-ips
                    - fortiguard-management
                    - forticloud
            logid:
                description:
                    - Log ID to trigger event.
            name:
                description:
                    - Name.
                required: true
            trigger-day:
                description:
                    - Day within a month to trigger.
            trigger-frequency:
                description:
                    - Scheduled trigger frequency (default = daily).
                choices:
                    - hourly
                    - daily
                    - weekly
                    - monthly
            trigger-hour:
                description:
                    - Hour of the day on which to trigger (0 - 23, default = 1).
            trigger-minute:
                description:
                    - Minute of the hour on which to trigger (0 - 59, 60 to randomize).
            trigger-type:
                description:
                    - Trigger type.
                choices:
                    - event-based
                    - scheduled
            trigger-weekday:
                description:
                    - Day of week for trigger.
                choices:
                    - sunday
                    - monday
                    - tuesday
                    - wednesday
                    - thursday
                    - friday
                    - saturday
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Trigger for automation stitches.
    fortios_system_automation_trigger:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_automation_trigger:
        state: "present"
        event-type: "ioc"
        ioc-level: "medium"
        license-type: "forticare-support"
        logid: "6"
        name: "default_name_7"
        trigger-day: "8"
        trigger-frequency: "hourly"
        trigger-hour: "10"
        trigger-minute: "11"
        trigger-type: "event-based"
        trigger-weekday: "sunday"
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


def filter_system_automation_trigger_data(json):
    option_list = ['event-type', 'ioc-level', 'license-type',
                   'logid', 'name', 'trigger-day',
                   'trigger-frequency', 'trigger-hour', 'trigger-minute',
                   'trigger-type', 'trigger-weekday']
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


def system_automation_trigger(data, fos):
    vdom = data['vdom']
    system_automation_trigger_data = data['system_automation_trigger']
    flattened_data = flatten_multilists_attributes(system_automation_trigger_data)
    filtered_data = filter_system_automation_trigger_data(flattened_data)
    if system_automation_trigger_data['state'] == "present":
        return fos.set('system',
                       'automation-trigger',
                       data=filtered_data,
                       vdom=vdom)

    elif system_automation_trigger_data['state'] == "absent":
        return fos.delete('system',
                          'automation-trigger',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data, fos)

    if data['system_automation_trigger']:
        resp = system_automation_trigger(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_automation_trigger": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "event-type": {"required": False, "type": "str",
                               "choices": ["ioc", "event-log", "reboot",
                                           "low-memory", "high-cpu", "license-near-expiry",
                                           "ha-failover", "config-change", "security-rating-summary",
                                           "virus-ips-db-updated"]},
                "ioc-level": {"required": False, "type": "str",
                              "choices": ["medium", "high"]},
                "license-type": {"required": False, "type": "str",
                                 "choices": ["forticare-support", "fortiguard-webfilter", "fortiguard-antispam",
                                             "fortiguard-antivirus", "fortiguard-ips", "fortiguard-management",
                                             "forticloud"]},
                "logid": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "trigger-day": {"required": False, "type": "int"},
                "trigger-frequency": {"required": False, "type": "str",
                                      "choices": ["hourly", "daily", "weekly",
                                                  "monthly"]},
                "trigger-hour": {"required": False, "type": "int"},
                "trigger-minute": {"required": False, "type": "int"},
                "trigger-type": {"required": False, "type": "str",
                                 "choices": ["event-based", "scheduled"]},
                "trigger-weekday": {"required": False, "type": "str",
                                    "choices": ["sunday", "monday", "tuesday",
                                                "wednesday", "thursday", "friday",
                                                "saturday"]}

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

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
