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
module: fortios_ips_custom
short_description: Configure IPS custom signature in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify ips feature and custom category.
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
    ips_custom:
        description:
            - Configure IPS custom signature.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            action:
                description:
                    - Default action (pass or block) for this signature.
                choices:
                    - pass
                    - block
            application:
                description:
                    - Applications to be protected. Blank for all applications.
            comment:
                description:
                    - Comment.
            location:
                description:
                    - Protect client or server traffic.
            log:
                description:
                    - Enable/disable logging.
                choices:
                    - disable
                    - enable
            log-packet:
                description:
                    - Enable/disable packet logging.
                choices:
                    - disable
                    - enable
            os:
                description:
                    - Operating system(s) that the signature protects. Blank for all operating systems.
            protocol:
                description:
                    - Protocol(s) that the signature scans. Blank for all protocols.
            rule-id:
                description:
                    - Signature ID.
            severity:
                description:
                    - Relative severity of the signature, from info to critical. Log messages generated by the signature include the severity.
            sig-name:
                description:
                    - Signature name.
            signature:
                description:
                    - Custom signature enclosed in single quotes.
            status:
                description:
                    - Enable/disable this signature.
                choices:
                    - disable
                    - enable
            tag:
                description:
                    - Signature tag.
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
  - name: Configure IPS custom signature.
    fortios_ips_custom:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      ips_custom:
        state: "present"
        action: "pass"
        application: "<your_own_value>"
        comment: "Comment."
        location: "<your_own_value>"
        log: "disable"
        log-packet: "disable"
        os: "<your_own_value>"
        protocol: "<your_own_value>"
        rule-id: "11"
        severity: "<your_own_value>"
        sig-name: "<your_own_value>"
        signature: "<your_own_value>"
        status: "disable"
        tag: "<your_own_value>"
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


def filter_ips_custom_data(json):
    option_list = ['action', 'application', 'comment',
                   'location', 'log', 'log-packet',
                   'os', 'protocol', 'rule-id',
                   'severity', 'sig-name', 'signature',
                   'status', 'tag']
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


def ips_custom(data, fos):
    vdom = data['vdom']
    ips_custom_data = data['ips_custom']
    flattened_data = flatten_multilists_attributes(ips_custom_data)
    filtered_data = filter_ips_custom_data(flattened_data)
    if ips_custom_data['state'] == "present":
        return fos.set('ips',
                       'custom',
                       data=filtered_data,
                       vdom=vdom)

    elif ips_custom_data['state'] == "absent":
        return fos.delete('ips',
                          'custom',
                          mkey=filtered_data['tag'],
                          vdom=vdom)


def fortios_ips(data, fos):
    login(data, fos)

    if data['ips_custom']:
        resp = ips_custom(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ips_custom": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "action": {"required": False, "type": "str",
                           "choices": ["pass", "block"]},
                "application": {"required": False, "type": "str"},
                "comment": {"required": False, "type": "str"},
                "location": {"required": False, "type": "str"},
                "log": {"required": False, "type": "str",
                        "choices": ["disable", "enable"]},
                "log-packet": {"required": False, "type": "str",
                               "choices": ["disable", "enable"]},
                "os": {"required": False, "type": "str"},
                "protocol": {"required": False, "type": "str"},
                "rule-id": {"required": False, "type": "int"},
                "severity": {"required": False, "type": "str"},
                "sig-name": {"required": False, "type": "str"},
                "signature": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["disable", "enable"]},
                "tag": {"required": True, "type": "str"}

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

    is_error, has_changed, result = fortios_ips(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
