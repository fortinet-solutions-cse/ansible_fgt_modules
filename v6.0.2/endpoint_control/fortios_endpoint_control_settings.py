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
module: fortios_endpoint_control_settings
short_description: Configure endpoint control settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify endpoint_control feature and settings category.
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
    endpoint_control_settings:
        description:
            - Configure endpoint control settings.
        default: null
        suboptions:
            download-custom-link:
                description:
                    - Customized URL for downloading FortiClient.
            download-location:
                description:
                    - FortiClient download location (FortiGuard or custom).
                choices:
                    - fortiguard
                    - custom
            forticlient-avdb-update-interval:
                description:
                    - Period of time between FortiClient AntiVirus database updates (0 - 24 hours, default = 8).
            forticlient-dereg-unsupported-client:
                description:
                    - Enable/disable deregistering unsupported FortiClient endpoints.
                choices:
                    - enable
                    - disable
            forticlient-ems-rest-api-call-timeout:
                description:
                    - FortiClient EMS call timeout in milliseconds (500 - 30000 milliseconds, default = 5000).
            forticlient-keepalive-interval:
                description:
                    - Interval between two KeepAlive messages from FortiClient (20 - 300 sec, default = 60).
            forticlient-offline-grace:
                description:
                    - Enable/disable grace period for offline registered clients.
                choices:
                    - enable
                    - disable
            forticlient-offline-grace-interval:
                description:
                    - Grace period for offline registered FortiClient (60 - 600 sec, default = 120).
            forticlient-reg-key:
                description:
                    - FortiClient registration key.
            forticlient-reg-key-enforce:
                description:
                    - Enable/disable requiring or enforcing FortiClient registration keys.
                choices:
                    - enable
                    - disable
            forticlient-reg-timeout:
                description:
                    - FortiClient registration license timeout (days, min = 1, max = 180, 0 means unlimited).
            forticlient-sys-update-interval:
                description:
                    - Interval between two system update messages from FortiClient (30 - 1440 min, default = 720).
            forticlient-user-avatar:
                description:
                    - Enable/disable uploading FortiClient user avatars.
                choices:
                    - enable
                    - disable
            forticlient-warning-interval:
                description:
                    - Period of time between FortiClient portal warnings (0 - 24 hours, default = 1).
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure endpoint control settings.
    fortios_endpoint_control_settings:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      endpoint_control_settings:
        download-custom-link: "<your_own_value>"
        download-location: "fortiguard"
        forticlient-avdb-update-interval: "5"
        forticlient-dereg-unsupported-client: "enable"
        forticlient-ems-rest-api-call-timeout: "7"
        forticlient-keepalive-interval: "8"
        forticlient-offline-grace: "enable"
        forticlient-offline-grace-interval: "10"
        forticlient-reg-key: "<your_own_value>"
        forticlient-reg-key-enforce: "enable"
        forticlient-reg-timeout: "13"
        forticlient-sys-update-interval: "14"
        forticlient-user-avatar: "enable"
        forticlient-warning-interval: "16"
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


def filter_endpoint_control_settings_data(json):
    option_list = ['download-custom-link', 'download-location', 'forticlient-avdb-update-interval',
                   'forticlient-dereg-unsupported-client', 'forticlient-ems-rest-api-call-timeout', 'forticlient-keepalive-interval',
                   'forticlient-offline-grace', 'forticlient-offline-grace-interval', 'forticlient-reg-key',
                   'forticlient-reg-key-enforce', 'forticlient-reg-timeout', 'forticlient-sys-update-interval',
                   'forticlient-user-avatar', 'forticlient-warning-interval']
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


def endpoint_control_settings(data, fos):
    vdom = data['vdom']
    endpoint_control_settings_data = data['endpoint_control_settings']
    flattened_data = flatten_multilists_attributes(endpoint_control_settings_data)
    filtered_data = filter_endpoint_control_settings_data(flattened_data)
    return fos.set('endpoint-control',
                   'settings',
                   data=filtered_data,
                   vdom=vdom)


def fortios_endpoint_control(data, fos):
    login(data, fos)

    if data['endpoint_control_settings']:
        resp = endpoint_control_settings(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "endpoint_control_settings": {
            "required": False, "type": "dict",
            "options": {
                "download-custom-link": {"required": False, "type": "str"},
                "download-location": {"required": False, "type": "str",
                                      "choices": ["fortiguard", "custom"]},
                "forticlient-avdb-update-interval": {"required": False, "type": "int"},
                "forticlient-dereg-unsupported-client": {"required": False, "type": "str",
                                                         "choices": ["enable", "disable"]},
                "forticlient-ems-rest-api-call-timeout": {"required": False, "type": "int"},
                "forticlient-keepalive-interval": {"required": False, "type": "int"},
                "forticlient-offline-grace": {"required": False, "type": "str",
                                              "choices": ["enable", "disable"]},
                "forticlient-offline-grace-interval": {"required": False, "type": "int"},
                "forticlient-reg-key": {"required": False, "type": "str"},
                "forticlient-reg-key-enforce": {"required": False, "type": "str",
                                                "choices": ["enable", "disable"]},
                "forticlient-reg-timeout": {"required": False, "type": "int"},
                "forticlient-sys-update-interval": {"required": False, "type": "int"},
                "forticlient-user-avatar": {"required": False, "type": "str",
                                            "choices": ["enable", "disable"]},
                "forticlient-warning-interval": {"required": False, "type": "int"}

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

    is_error, has_changed, result = fortios_endpoint_control(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
