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
module: fortios_user_tacacsplus
short_description: Configure TACACS+ server entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify user feature and tacacsplus category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.5
version_added: "2.9"
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
            - FortiOS or FortiGate IP address.
        type: str
        required: true
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        choices:
            - present
            - absent
    user_tacacsplus:
        description:
            - Configure TACACS+ server entries.
        default: null
        type: dict
        suboptions:
            authen_type:
                description:
                    - Allowed authentication protocols/methods.
                choices:
                    - mschap
                    - chap
                    - pap
                    - ascii
                    - auto
            authorization:
                description:
                    - Enable/disable TACACS+ authorization.
                choices:
                    - enable
                    - disable
            key:
                description:
                    - Key to access the primary server.
            name:
                description:
                    - TACACS+ server entry name.
                required: true
            port:
                description:
                    - Port number of the TACACS+ server.
            secondary_key:
                description:
                    - Key to access the secondary server.
            secondary_server:
                description:
                    - Secondary TACACS+ server CN domain name or IP address.
            server:
                description:
                    - Primary TACACS+ server CN domain name or IP address.
            source_ip:
                description:
                    - source IP for communications to TACACS+ server.
            tertiary_key:
                description:
                    - Key to access the tertiary server.
            tertiary_server:
                description:
                    - Tertiary TACACS+ server CN domain name or IP address.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure TACACS+ server entries.
    fortios_user_tacacsplus:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      user_tacacsplus:
        authen_type: "mschap"
        authorization: "enable"
        key: "<your_own_value>"
        name: "default_name_6"
        port: "7"
        secondary_key: "<your_own_value>"
        secondary_server: "<your_own_value>"
        server: "192.168.100.40"
        source_ip: "84.230.14.43"
        tertiary_key: "<your_own_value>"
        tertiary_server: "<your_own_value>"
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
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortios.fortios import FortiOSHandler
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG


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


def filter_user_tacacsplus_data(json):
    option_list = ['authen_type', 'authorization', 'key',
                   'name', 'port', 'secondary_key',
                   'secondary_server', 'server', 'source_ip',
                   'tertiary_key', 'tertiary_server']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for elem in data:
            elem = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def user_tacacsplus(data, fos):
    vdom = data['vdom']
    state = data['state']
    user_tacacsplus_data = data['user_tacacsplus']
    filtered_data = underscore_to_hyphen(filter_user_tacacsplus_data(user_tacacsplus_data))

    if state == "present":
        return fos.set('user',
                       'tacacs+',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('user',
                          'tacacs+',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_user(data, fos):

    if data['user_tacacsplus']:
        resp = user_tacacsplus(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "user_tacacsplus": {
            "required": False, "type": "dict",
            "options": {
                "authen_type": {"required": False, "type": "str",
                                "choices": ["mschap", "chap", "pap",
                                            "ascii", "auto"]},
                "authorization": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "key": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "port": {"required": False, "type": "int"},
                "secondary_key": {"required": False, "type": "str"},
                "secondary_server": {"required": False, "type": "str"},
                "server": {"required": False, "type": "str"},
                "source_ip": {"required": False, "type": "str"},
                "tertiary_key": {"required": False, "type": "str"},
                "tertiary_server": {"required": False, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_user(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_user(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
