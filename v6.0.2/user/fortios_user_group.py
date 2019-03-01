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
module: fortios_user_group
short_description: Configure user groups in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify user feature and group category.
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
    user_group:
        description:
            - Configure user groups.
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
                    - Enable/disable overriding the global number of concurrent authentication sessions for this user group.
                choices:
                    - enable
                    - disable
            auth-concurrent-value:
                description:
                    - Maximum number of concurrent authenticated connections per user (0 - 100).
            authtimeout:
                description:
                    - Authentication timeout in minutes for this user group. 0 to use the global user setting auth-timeout.
            company:
                description:
                    - Set the action for the company guest user field.
                choices:
                    - optional
                    - mandatory
                    - disabled
            email:
                description:
                    - Enable/disable the guest user email address field.
                choices:
                    - disable
                    - enable
            expire:
                description:
                    - Time in seconds before guest user accounts expire. (1 - 31536000 sec)
            expire-type:
                description:
                    - Determine when the expiration countdown begins.
                choices:
                    - immediately
                    - first-successful-login
            group-type:
                description:
                    - Set the group to be for firewall authentication, FSSO, RSSO, or guest users.
                choices:
                    - firewall
                    - fsso-service
                    - rsso
                    - guest
            guest:
                description:
                    - Guest User.
                suboptions:
                    comment:
                        description:
                            - Comment.
                    company:
                        description:
                            - Set the action for the company guest user field.
                    email:
                        description:
                            - Email.
                    expiration:
                        description:
                            - Expire time.
                    mobile-phone:
                        description:
                            - Mobile phone.
                    name:
                        description:
                            - Guest name.
                    password:
                        description:
                            - Guest password.
                    sponsor:
                        description:
                            - Set the action for the sponsor guest user field.
                    user-id:
                        description:
                            - Guest ID.
                        required: true
            http-digest-realm:
                description:
                    - Realm attribute for MD5-digest authentication.
            id:
                description:
                    - Group ID.
            match:
                description:
                    - Group matches.
                suboptions:
                    group-name:
                        description:
                            - Name of matching group on remote auththentication server.
                    id:
                        description:
                            - ID.
                        required: true
                    server-name:
                        description:
                            - Name of remote auth server. Source user.radius.name user.ldap.name user.tacacs+.name.
            max-accounts:
                description:
                    - Maximum number of guest accounts that can be created for this group (0 means unlimited).
            member:
                description:
                    - Names of users, peers, LDAP severs, or RADIUS servers to add to the user group.
                suboptions:
                    name:
                        description:
                            - Group member name. Source user.peer.name user.local.name user.radius.name user.tacacs+.name user.ldap.name user.adgrp.name user
                              .pop3.name.
                        required: true
            mobile-phone:
                description:
                    - Enable/disable the guest user mobile phone number field.
                choices:
                    - disable
                    - enable
            multiple-guest-add:
                description:
                    - Enable/disable addition of multiple guests.
                choices:
                    - disable
                    - enable
            name:
                description:
                    - Group name.
                required: true
            password:
                description:
                    - Guest user password type.
                choices:
                    - auto-generate
                    - specify
                    - disable
            sms-custom-server:
                description:
                    - SMS server. Source system.sms-server.name.
            sms-server:
                description:
                    - Send SMS through FortiGuard or other external server.
                choices:
                    - fortiguard
                    - custom
            sponsor:
                description:
                    - Set the action for the sponsor guest user field.
                choices:
                    - optional
                    - mandatory
                    - disabled
            sso-attribute-value:
                description:
                    - Name of the RADIUS user group that this local user group represents.
            user-id:
                description:
                    - Guest user ID type.
                choices:
                    - email
                    - auto-generate
                    - specify
            user-name:
                description:
                    - Enable/disable the guest user name entry.
                choices:
                    - disable
                    - enable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure user groups.
    fortios_user_group:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      user_group:
        state: "present"
        auth-concurrent-override: "enable"
        auth-concurrent-value: "4"
        authtimeout: "5"
        company: "optional"
        email: "disable"
        expire: "8"
        expire-type: "immediately"
        group-type: "firewall"
        guest:
         -
            comment: "Comment."
            company: "<your_own_value>"
            email: "<your_own_value>"
            expiration: "<your_own_value>"
            mobile-phone: "<your_own_value>"
            name: "default_name_17"
            password: "<your_own_value>"
            sponsor: "<your_own_value>"
            user-id: "<your_own_value>"
        http-digest-realm: "<your_own_value>"
        id:  "22"
        match:
         -
            group-name: "<your_own_value>"
            id:  "25"
            server-name: "<your_own_value> (source user.radius.name user.ldap.name user.tacacs+.name)"
        max-accounts: "27"
        member:
         -
            name: "default_name_29 (source user.peer.name user.local.name user.radius.name user.tacacs+.name user.ldap.name user.adgrp.name user.pop3.name)"
        mobile-phone: "disable"
        multiple-guest-add: "disable"
        name: "default_name_32"
        password: "auto-generate"
        sms-custom-server: "<your_own_value> (source system.sms-server.name)"
        sms-server: "fortiguard"
        sponsor: "optional"
        sso-attribute-value: "<your_own_value>"
        user-id: "email"
        user-name: "disable"
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


def filter_user_group_data(json):
    option_list = ['auth-concurrent-override', 'auth-concurrent-value', 'authtimeout',
                   'company', 'email', 'expire',
                   'expire-type', 'group-type', 'guest',
                   'http-digest-realm', 'id', 'match',
                   'max-accounts', 'member', 'mobile-phone',
                   'multiple-guest-add', 'name', 'password',
                   'sms-custom-server', 'sms-server', 'sponsor',
                   'sso-attribute-value', 'user-id', 'user-name']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def user_group(data, fos):
    vdom = data['vdom']
    user_group_data = data['user_group']
    filtered_data = filter_user_group_data(user_group_data)

    if user_group_data['state'] == "present":
        return fos.set('user',
                       'group',
                       data=filtered_data,
                       vdom=vdom)

    elif user_group_data['state'] == "absent":
        return fos.delete('user',
                          'group',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_user(data, fos):
    login(data, fos)

    if data['user_group']:
        resp = user_group(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "user_group": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "auth-concurrent-override": {"required": False, "type": "str",
                                             "choices": ["enable", "disable"]},
                "auth-concurrent-value": {"required": False, "type": "int"},
                "authtimeout": {"required": False, "type": "int"},
                "company": {"required": False, "type": "str",
                            "choices": ["optional", "mandatory", "disabled"]},
                "email": {"required": False, "type": "str",
                          "choices": ["disable", "enable"]},
                "expire": {"required": False, "type": "int"},
                "expire-type": {"required": False, "type": "str",
                                "choices": ["immediately", "first-successful-login"]},
                "group-type": {"required": False, "type": "str",
                               "choices": ["firewall", "fsso-service", "rsso",
                                           "guest"]},
                "guest": {"required": False, "type": "list",
                          "options": {
                              "comment": {"required": False, "type": "str"},
                              "company": {"required": False, "type": "str"},
                              "email": {"required": False, "type": "str"},
                              "expiration": {"required": False, "type": "str"},
                              "mobile-phone": {"required": False, "type": "str"},
                              "name": {"required": False, "type": "str"},
                              "password": {"required": False, "type": "str"},
                              "sponsor": {"required": False, "type": "str"},
                              "user-id": {"required": True, "type": "str"}
                          }},
                "http-digest-realm": {"required": False, "type": "str"},
                "id": {"required": False, "type": "int"},
                "match": {"required": False, "type": "list",
                          "options": {
                              "group-name": {"required": False, "type": "str"},
                              "id": {"required": True, "type": "int"},
                              "server-name": {"required": False, "type": "str"}
                          }},
                "max-accounts": {"required": False, "type": "int"},
                "member": {"required": False, "type": "list",
                           "options": {
                               "name": {"required": True, "type": "str"}
                           }},
                "mobile-phone": {"required": False, "type": "str",
                                 "choices": ["disable", "enable"]},
                "multiple-guest-add": {"required": False, "type": "str",
                                       "choices": ["disable", "enable"]},
                "name": {"required": True, "type": "str"},
                "password": {"required": False, "type": "str",
                             "choices": ["auto-generate", "specify", "disable"]},
                "sms-custom-server": {"required": False, "type": "str"},
                "sms-server": {"required": False, "type": "str",
                               "choices": ["fortiguard", "custom"]},
                "sponsor": {"required": False, "type": "str",
                            "choices": ["optional", "mandatory", "disabled"]},
                "sso-attribute-value": {"required": False, "type": "str"},
                "user-id": {"required": False, "type": "str",
                            "choices": ["email", "auto-generate", "specify"]},
                "user-name": {"required": False, "type": "str",
                              "choices": ["disable", "enable"]}

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
