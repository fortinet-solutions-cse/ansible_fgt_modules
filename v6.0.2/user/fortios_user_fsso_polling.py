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
module: fortios_user_fsso_polling
short_description: Configure FSSO active directory servers for polling mode in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify user feature and fsso_polling category.
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
    user_fsso_polling:
        description:
            - Configure FSSO active directory servers for polling mode.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            adgrp:
                description:
                    - LDAP Group Info.
                suboptions:
                    name:
                        description:
                            - Name.
                        required: true
            default-domain:
                description:
                    - Default domain managed by this Active Directory server.
            id:
                description:
                    - Active Directory server ID.
                required: true
            ldap-server:
                description:
                    - LDAP server name used in LDAP connection strings. Source user.ldap.name.
            logon-history:
                description:
                    - Number of hours of logon history to keep, 0 means keep all history.
            password:
                description:
                    - Password required to log into this Active Directory server
            polling-frequency:
                description:
                    - Polling frequency (every 1 to 30 seconds).
            port:
                description:
                    - Port to communicate with this Active Directory server.
            server:
                description:
                    - Host name or IP address of the Active Directory server.
            status:
                description:
                    - Enable/disable polling for the status of this Active Directory server.
                choices:
                    - enable
                    - disable
            user:
                description:
                    - User name required to log into this Active Directory server.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure FSSO active directory servers for polling mode.
    fortios_user_fsso_polling:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      user_fsso_polling:
        state: "present"
        adgrp:
         -
            name: "default_name_4"
        default-domain: "<your_own_value>"
        id:  "6"
        ldap-server: "<your_own_value> (source user.ldap.name)"
        logon-history: "8"
        password: "<your_own_value>"
        polling-frequency: "10"
        port: "11"
        server: "192.168.100.40"
        status: "enable"
        user: "<your_own_value>"
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


def filter_user_fsso_polling_data(json):
    option_list = ['adgrp', 'default-domain', 'id',
                   'ldap-server', 'logon-history', 'password',
                   'polling-frequency', 'port', 'server',
                   'status', 'user']
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


def user_fsso_polling(data, fos):
    vdom = data['vdom']
    user_fsso_polling_data = data['user_fsso_polling']
    flattened_data = flatten_multilists_attributes(user_fsso_polling_data)
    filtered_data = filter_user_fsso_polling_data(flattened_data)
    if user_fsso_polling_data['state'] == "present":
        return fos.set('user',
                       'fsso-polling',
                       data=filtered_data,
                       vdom=vdom)

    elif user_fsso_polling_data['state'] == "absent":
        return fos.delete('user',
                          'fsso-polling',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_user(data, fos):
    login(data)

    if data['user_fsso_polling']:
        resp = user_fsso_polling(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "user_fsso_polling": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "adgrp": {"required": False, "type": "list",
                          "options": {
                              "name": {"required": True, "type": "str"}
                          }},
                "default-domain": {"required": False, "type": "str"},
                "id": {"required": True, "type": "int"},
                "ldap-server": {"required": False, "type": "str"},
                "logon-history": {"required": False, "type": "int"},
                "password": {"required": False, "type": "str"},
                "polling-frequency": {"required": False, "type": "int"},
                "port": {"required": False, "type": "int"},
                "server": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "user": {"required": False, "type": "str"}

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
