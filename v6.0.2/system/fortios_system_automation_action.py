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
module: fortios_system_automation_action
short_description: Action for automation stitches in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and automation_action category.
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
    system_automation_action:
        description:
            - Action for automation stitches.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            action-type:
                description:
                    - Action type.
                choices:
                    - email
                    - ios-notification
                    - alert
                    - disable-ssid
                    - quarantine
                    - quarantine-forticlient
                    - ban-ip
                    - aws-lambda
                    - webhook
            aws-api-id:
                description:
                    - AWS API Gateway ID.
            aws-api-key:
                description:
                    - AWS API Gateway API key.
            aws-api-path:
                description:
                    - AWS API Gateway path.
            aws-api-stage:
                description:
                    - AWS API Gateway deployment stage name.
            aws-region:
                description:
                    - AWS region.
            delay:
                description:
                    - Delay before execution (in seconds).
            email-subject:
                description:
                    - Email subject.
            email-to:
                description:
                    - Email addresses.
                suboptions:
                    name:
                        description:
                            - Email address.
                        required: true
            headers:
                description:
                    - Request headers.
                suboptions:
                    header:
                        description:
                            - Request header.
                        required: true
            http-body:
                description:
                    - Request body (if necessary). Should be serialized json string.
            method:
                description:
                    - Request method (GET, POST or PUT).
                choices:
                    - post
                    - put
                    - get
            minimum-interval:
                description:
                    - Limit execution to no more than once in this interval (in seconds).
            name:
                description:
                    - Name.
                required: true
            port:
                description:
                    - Protocol port.
            protocol:
                description:
                    - Request protocol.
                choices:
                    - http
                    - https
            required:
                description:
                    - Required in action chain.
                choices:
                    - enable
                    - disable
            uri:
                description:
                    - Request API URI.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Action for automation stitches.
    fortios_system_automation_action:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_automation_action:
        state: "present"
        action-type: "email"
        aws-api-id: "<your_own_value>"
        aws-api-key: "<your_own_value>"
        aws-api-path: "<your_own_value>"
        aws-api-stage: "<your_own_value>"
        aws-region: "<your_own_value>"
        delay: "9"
        email-subject: "<your_own_value>"
        email-to:
         -
            name: "default_name_12"
        headers:
         -
            header: "<your_own_value>"
        http-body: "<your_own_value>"
        method: "post"
        minimum-interval: "17"
        name: "default_name_18"
        port: "19"
        protocol: "http"
        required: "enable"
        uri: "<your_own_value>"
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


def filter_system_automation_action_data(json):
    option_list = ['action-type', 'aws-api-id', 'aws-api-key',
                   'aws-api-path', 'aws-api-stage', 'aws-region',
                   'delay', 'email-subject', 'email-to',
                   'headers', 'http-body', 'method',
                   'minimum-interval', 'name', 'port',
                   'protocol', 'required', 'uri']
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


def system_automation_action(data, fos):
    vdom = data['vdom']
    system_automation_action_data = data['system_automation_action']
    flattened_data = flatten_multilists_attributes(system_automation_action_data)
    filtered_data = filter_system_automation_action_data(flattened_data)
    if system_automation_action_data['state'] == "present":
        return fos.set('system',
                       'automation-action',
                       data=filtered_data,
                       vdom=vdom)

    elif system_automation_action_data['state'] == "absent":
        return fos.delete('system',
                          'automation-action',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    if data['system_automation_action']:
        resp = system_automation_action(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_automation_action": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "action-type": {"required": False, "type": "str",
                                "choices": ["email", "ios-notification", "alert",
                                            "disable-ssid", "quarantine", "quarantine-forticlient",
                                            "ban-ip", "aws-lambda", "webhook"]},
                "aws-api-id": {"required": False, "type": "str"},
                "aws-api-key": {"required": False, "type": "str"},
                "aws-api-path": {"required": False, "type": "str"},
                "aws-api-stage": {"required": False, "type": "str"},
                "aws-region": {"required": False, "type": "str"},
                "delay": {"required": False, "type": "int"},
                "email-subject": {"required": False, "type": "str"},
                "email-to": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "headers": {"required": False, "type": "list",
                            "options": {
                                "header": {"required": True, "type": "str"}
                            }},
                "http-body": {"required": False, "type": "str"},
                "method": {"required": False, "type": "str",
                           "choices": ["post", "put", "get"]},
                "minimum-interval": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "port": {"required": False, "type": "int"},
                "protocol": {"required": False, "type": "str",
                             "choices": ["http", "https"]},
                "required": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "uri": {"required": False, "type": "str"}

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
