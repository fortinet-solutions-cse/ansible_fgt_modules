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
module: fortios_user_local
short_description: Configure local users in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify user feature and local category.
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
    user_local:
        description:
            - Configure local users.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            auth-concurrent-override:
                description:
                    - Enable/disable overriding the policy-auth-concurrent under config system global.
                choices:
                    - enable
                    - disable
            auth-concurrent-value:
                description:
                    - Maximum number of concurrent logins permitted from the same user.
            authtimeout:
                description:
                    - Time in minutes before the authentication timeout for a user is reached.
            email-to:
                description:
                    - Two-factor recipient's email address.
            fortitoken:
                description:
                    - Two-factor recipient's FortiToken serial number. Source user.fortitoken.serial-number.
            id:
                description:
                    - User ID.
            ldap-server:
                description:
                    - Name of LDAP server with which the user must authenticate. Source user.ldap.name.
            name:
                description:
                    - User name.
                required: true
            passwd:
                description:
                    - User's password.
            passwd-policy:
                description:
                    - Password policy to apply to this user, as defined in config user password-policy. Source user.password-policy.name.
            passwd-time:
                description:
                    - Time of the last password update.
            ppk-identity:
                description:
                    - IKEv2 Postquantum Preshared Key Identity.
            ppk-secret:
                description:
                    - IKEv2 Postquantum Preshared Key (ASCII string or hexadecimal encoded with a leading 0x).
            radius-server:
                description:
                    - Name of RADIUS server with which the user must authenticate. Source user.radius.name.
            sms-custom-server:
                description:
                    - Two-factor recipient's SMS server. Source system.sms-server.name.
            sms-phone:
                description:
                    - Two-factor recipient's mobile phone number.
            sms-server:
                description:
                    - Send SMS through FortiGuard or other external server.
                choices:
                    - fortiguard
                    - custom
            status:
                description:
                    - Enable/disable allowing the local user to authenticate with the FortiGate unit.
                choices:
                    - enable
                    - disable
            tacacs+-server:
                description:
                    - Name of TACACS+ server with which the user must authenticate. Source user.tacacs+.name.
            two-factor:
                description:
                    - Enable/disable two-factor authentication.
                choices:
                    - disable
                    - fortitoken
                    - email
                    - sms
            type:
                description:
                    - Authentication method.
                choices:
                    - password
                    - radius
                    - tacacs+
                    - ldap
            workstation:
                description:
                    - Name of the remote user workstation, if you want to limit the user to authenticate only from a particular workstation.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure local users.
    fortios_user_local:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      user_local:
        state: "present"
        auth-concurrent-override: "enable"
        auth-concurrent-value: "4"
        authtimeout: "5"
        email-to: "<your_own_value>"
        fortitoken: "<your_own_value> (source user.fortitoken.serial-number)"
        id:  "8"
        ldap-server: "<your_own_value> (source user.ldap.name)"
        name: "default_name_10"
        passwd: "<your_own_value>"
        passwd-policy: "<your_own_value> (source user.password-policy.name)"
        passwd-time: "<your_own_value>"
        ppk-identity: "<your_own_value>"
        ppk-secret: "<your_own_value>"
        radius-server: "<your_own_value> (source user.radius.name)"
        sms-custom-server: "<your_own_value> (source system.sms-server.name)"
        sms-phone: "<your_own_value>"
        sms-server: "fortiguard"
        status: "enable"
        tacacs+-server: "<your_own_value> (source user.tacacs+.name)"
        two-factor: "disable"
        type: "password"
        workstation: "<your_own_value>"
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


def filter_user_local_data(json):
    option_list = ['auth-concurrent-override', 'auth-concurrent-value', 'authtimeout',
                   'email-to', 'fortitoken', 'id',
                   'ldap-server', 'name', 'passwd',
                   'passwd-policy', 'passwd-time', 'ppk-identity',
                   'ppk-secret', 'radius-server', 'sms-custom-server',
                   'sms-phone', 'sms-server', 'status',
                   'tacacs+-server', 'two-factor', 'type',
                   'workstation']
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


def user_local(data, fos):
    vdom = data['vdom']
    user_local_data = data['user_local']
    flattened_data = flatten_multilists_attributes(user_local_data)
    filtered_data = filter_user_local_data(flattened_data)
    if user_local_data['state'] == "present":
        return fos.set('user',
                       'local',
                       data=filtered_data,
                       vdom=vdom)

    elif user_local_data['state'] == "absent":
        return fos.delete('user',
                          'local',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_user(data, fos):
    login(data, fos)

    if data['user_local']:
        resp = user_local(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "user_local": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "auth-concurrent-override": {"required": False, "type": "str",
                                             "choices": ["enable", "disable"]},
                "auth-concurrent-value": {"required": False, "type": "int"},
                "authtimeout": {"required": False, "type": "int"},
                "email-to": {"required": False, "type": "str"},
                "fortitoken": {"required": False, "type": "str"},
                "id": {"required": False, "type": "int"},
                "ldap-server": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "passwd": {"required": False, "type": "str"},
                "passwd-policy": {"required": False, "type": "str"},
                "passwd-time": {"required": False, "type": "str"},
                "ppk-identity": {"required": False, "type": "str"},
                "ppk-secret": {"required": False, "type": "password-3"},
                "radius-server": {"required": False, "type": "str"},
                "sms-custom-server": {"required": False, "type": "str"},
                "sms-phone": {"required": False, "type": "str"},
                "sms-server": {"required": False, "type": "str",
                               "choices": ["fortiguard", "custom"]},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "tacacs+-server": {"required": False, "type": "str"},
                "two-factor": {"required": False, "type": "str",
                               "choices": ["disable", "fortitoken", "email",
                                           "sms"]},
                "type": {"required": False, "type": "str",
                         "choices": ["password", "radius", "tacacs+",
                                     "ldap"]},
                "workstation": {"required": False, "type": "str"}

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
