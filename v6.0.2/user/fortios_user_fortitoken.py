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
module: fortios_user_fortitoken
short_description: Configure FortiToken.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure user feature and fortitoken category.
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
    user_fortitoken:
        description:
            - Configure FortiToken.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            activation-code:
                description:
                    - Mobile token user activation-code.
            activation-expire:
                description:
                    - Mobile token user activation-code expire time.
            comments:
                description:
                    - Comment.
            license:
                description:
                    - Mobile token license.
            os-ver:
                description:
                    - Device Mobile Version.
            reg-id:
                description:
                    - Device Reg ID.
            seed:
                description:
                    - Token seed.
            serial-number:
                description:
                    - Serial number.
                required: true
            status:
                description:
                    - Status
                choices:
                    - active
                    - lock
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure FortiToken.
    fortios_user_fortitoken:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      user_fortitoken:
        state: "present"
        activation-code: "<your_own_value>"
        activation-expire: "4"
        comments: "<your_own_value>"
        license: "<your_own_value>"
        os-ver: "<your_own_value>"
        reg-id: "<your_own_value>"
        seed: "<your_own_value>"
        serial-number: "<your_own_value>"
        status: "active"
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


def filter_user_fortitoken_data(json):
    option_list = ['activation-code', 'activation-expire', 'comments',
                   'license', 'os-ver', 'reg-id',
                   'seed', 'serial-number', 'status']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def user_fortitoken(data, fos):
    vdom = data['vdom']
    user_fortitoken_data = data['user_fortitoken']
    filtered_data = filter_user_fortitoken_data(user_fortitoken_data)
    if user_fortitoken_data['state'] == "present":
        return fos.set('user',
                       'fortitoken',
                       data=filtered_data,
                       vdom=vdom)

    elif user_fortitoken_data['state'] == "absent":
        return fos.delete('user',
                          'fortitoken',
                          mkey=filtered_data['serial-number'],
                          vdom=vdom)


def fortios_user(data, fos):
    login(data)

    methodlist = ['user_fortitoken']
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
        "user_fortitoken": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "activation-code": {"required": False, "type": "str"},
                "activation-expire": {"required": False, "type": "int"},
                "comments": {"required": False, "type": "str"},
                "license": {"required": False, "type": "str"},
                "os-ver": {"required": False, "type": "str"},
                "reg-id": {"required": False, "type": "str"},
                "seed": {"required": False, "type": "str"},
                "serial-number": {"required": True, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["active", "lock"]}

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

    is_error, has_changed, result = fortios_user(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
