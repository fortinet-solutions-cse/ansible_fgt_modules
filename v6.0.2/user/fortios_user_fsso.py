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
module: fortios_user_fsso
short_description: Configure Fortinet Single Sign On (FSSO) agents in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify user feature and fsso category.
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
    user_fsso:
        description:
            - Configure Fortinet Single Sign On (FSSO) agents.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            ldap-server:
                description:
                    - LDAP server to get group information. Source user.ldap.name.
            name:
                description:
                    - Name.
                required: true
            password:
                description:
                    - Password of the first FSSO collector agent.
            password2:
                description:
                    - Password of the second FSSO collector agent.
            password3:
                description:
                    - Password of the third FSSO collector agent.
            password4:
                description:
                    - Password of the fourth FSSO collector agent.
            password5:
                description:
                    - Password of the fifth FSSO collector agent.
            port:
                description:
                    - Port of the first FSSO collector agent.
            port2:
                description:
                    - Port of the second FSSO collector agent.
            port3:
                description:
                    - Port of the third FSSO collector agent.
            port4:
                description:
                    - Port of the fourth FSSO collector agent.
            port5:
                description:
                    - Port of the fifth FSSO collector agent.
            server:
                description:
                    - Domain name or IP address of the first FSSO collector agent.
            server2:
                description:
                    - Domain name or IP address of the second FSSO collector agent.
            server3:
                description:
                    - Domain name or IP address of the third FSSO collector agent.
            server4:
                description:
                    - Domain name or IP address of the fourth FSSO collector agent.
            server5:
                description:
                    - Domain name or IP address of the fifth FSSO collector agent.
            source-ip:
                description:
                    - Source IP for communications to FSSO agent.
            source-ip6:
                description:
                    - IPv6 source for communications to FSSO agent.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure Fortinet Single Sign On (FSSO) agents.
    fortios_user_fsso:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      user_fsso:
        state: "present"
        ldap-server: "<your_own_value> (source user.ldap.name)"
        name: "default_name_4"
        password: "<your_own_value>"
        password2: "<your_own_value>"
        password3: "<your_own_value>"
        password4: "<your_own_value>"
        password5: "<your_own_value>"
        port: "10"
        port2: "11"
        port3: "12"
        port4: "13"
        port5: "14"
        server: "192.168.100.40"
        server2: "<your_own_value>"
        server3: "<your_own_value>"
        server4: "<your_own_value>"
        server5: "<your_own_value>"
        source-ip: "84.230.14.43"
        source-ip6: "<your_own_value>"
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


def filter_user_fsso_data(json):
    option_list = ['ldap-server', 'name', 'password',
                   'password2', 'password3', 'password4',
                   'password5', 'port', 'port2',
                   'port3', 'port4', 'port5',
                   'server', 'server2', 'server3',
                   'server4', 'server5', 'source-ip',
                   'source-ip6']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def user_fsso(data, fos):
    vdom = data['vdom']
    user_fsso_data = data['user_fsso']
    filtered_data = filter_user_fsso_data(user_fsso_data)

    if user_fsso_data['state'] == "present":
        return fos.set('user',
                       'fsso',
                       data=filtered_data,
                       vdom=vdom)

    elif user_fsso_data['state'] == "absent":
        return fos.delete('user',
                          'fsso',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_user(data, fos):
    login(data, fos)

    if data['user_fsso']:
        resp = user_fsso(data, fos)

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
        "user_fsso": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "ldap-server": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "password": {"required": False, "type": "str"},
                "password2": {"required": False, "type": "str"},
                "password3": {"required": False, "type": "str"},
                "password4": {"required": False, "type": "str"},
                "password5": {"required": False, "type": "str"},
                "port": {"required": False, "type": "int"},
                "port2": {"required": False, "type": "int"},
                "port3": {"required": False, "type": "int"},
                "port4": {"required": False, "type": "int"},
                "port5": {"required": False, "type": "int"},
                "server": {"required": False, "type": "str"},
                "server2": {"required": False, "type": "str"},
                "server3": {"required": False, "type": "str"},
                "server4": {"required": False, "type": "str"},
                "server5": {"required": False, "type": "str"},
                "source-ip": {"required": False, "type": "str"},
                "source-ip6": {"required": False, "type": "str"}

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

    is_error, has_changed, result = fortios_user(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
