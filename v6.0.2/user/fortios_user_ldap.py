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
#
# the lib use python logging can get it if the following is set in your
# Ansible config.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_user_ldap
short_description: Configure LDAP server entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify user feature and ldap category.
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
    user_ldap:
        description:
            - Configure LDAP server entries.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            account-key-filter:
                description:
                    - Account key filter, using the UPN as the search filter.
            account-key-processing:
                description:
                    - Account key processing operation, either keep or strip domain string of UPN in the token.
                choices:
                    - same
                    - strip
            ca-cert:
                description:
                    - CA certificate name. Source vpn.certificate.ca.name.
            cnid:
                description:
                    - Common name identifier for the LDAP server. The common name identifier for most LDAP servers is "cn".
            dn:
                description:
                    - Distinguished name used to look up entries on the LDAP server.
            group-filter:
                description:
                    - Filter used for group matching.
            group-member-check:
                description:
                    - Group member checking methods.
                choices:
                    - user-attr
                    - group-object
                    - posix-group-object
            group-object-filter:
                description:
                    - Filter used for group searching.
            group-search-base:
                description:
                    - Search base used for group searching.
            member-attr:
                description:
                    - Name of attribute from which to get group membership.
            name:
                description:
                    - LDAP server entry name.
                required: true
            password:
                description:
                    - Password for initial binding.
            password-expiry-warning:
                description:
                    - Enable/disable password expiry warnings.
                choices:
                    - enable
                    - disable
            password-renewal:
                description:
                    - Enable/disable online password renewal.
                choices:
                    - enable
                    - disable
            port:
                description:
                    - Port to be used for communication with the LDAP server (default = 389).
            secondary-server:
                description:
                    - Secondary LDAP server CN domain name or IP.
            secure:
                description:
                    - Port to be used for authentication.
                choices:
                    - disable
                    - starttls
                    - ldaps
            server:
                description:
                    - LDAP server CN domain name or IP.
            source-ip:
                description:
                    - Source IP for communications to LDAP server.
            ssl-min-proto-version:
                description:
                    - Minimum supported protocol version for SSL/TLS connections (default is to follow system global setting).
                choices:
                    - default
                    - SSLv3
                    - TLSv1
                    - TLSv1-1
                    - TLSv1-2
            tertiary-server:
                description:
                    - Tertiary LDAP server CN domain name or IP.
            type:
                description:
                    - Authentication type for LDAP searches.
                choices:
                    - simple
                    - anonymous
                    - regular
            username:
                description:
                    - Username (full DN) for initial binding.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure LDAP server entries.
    fortios_user_ldap:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      user_ldap:
        state: "present"
        account-key-filter: "<your_own_value>"
        account-key-processing: "same"
        ca-cert: "<your_own_value> (source vpn.certificate.ca.name)"
        cnid: "<your_own_value>"
        dn: "<your_own_value>"
        group-filter: "<your_own_value>"
        group-member-check: "user-attr"
        group-object-filter: "<your_own_value>"
        group-search-base: "<your_own_value>"
        member-attr: "<your_own_value>"
        name: "default_name_13"
        password: "<your_own_value>"
        password-expiry-warning: "enable"
        password-renewal: "enable"
        port: "17"
        secondary-server: "<your_own_value>"
        secure: "disable"
        server: "192.168.100.40"
        source-ip: "84.230.14.43"
        ssl-min-proto-version: "default"
        tertiary-server: "<your_own_value>"
        type: "simple"
        username: "<your_own_value>"
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


def filter_user_ldap_data(json):
    option_list = ['account-key-filter', 'account-key-processing', 'ca-cert',
                   'cnid', 'dn', 'group-filter',
                   'group-member-check', 'group-object-filter', 'group-search-base',
                   'member-attr', 'name', 'password',
                   'password-expiry-warning', 'password-renewal', 'port',
                   'secondary-server', 'secure', 'server',
                   'source-ip', 'ssl-min-proto-version', 'tertiary-server',
                   'type', 'username']
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


def user_ldap(data, fos):
    vdom = data['vdom']
    user_ldap_data = data['user_ldap']
    flattened_data = flatten_multilists_attributes(user_ldap_data)
    filtered_data = filter_user_ldap_data(flattened_data)
    if user_ldap_data['state'] == "present":
        return fos.set('user',
                       'ldap',
                       data=filtered_data,
                       vdom=vdom)

    elif user_ldap_data['state'] == "absent":
        return fos.delete('user',
                          'ldap',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_user(data, fos):
    login(data)

    methodlist = ['user_ldap']
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
        "https": {"required": False, "type": "bool", "default": True},
        "user_ldap": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "account-key-filter": {"required": False, "type": "str"},
                "account-key-processing": {"required": False, "type": "str",
                                           "choices": ["same", "strip"]},
                "ca-cert": {"required": False, "type": "str"},
                "cnid": {"required": False, "type": "str"},
                "dn": {"required": False, "type": "str"},
                "group-filter": {"required": False, "type": "str"},
                "group-member-check": {"required": False, "type": "str",
                                       "choices": ["user-attr", "group-object", "posix-group-object"]},
                "group-object-filter": {"required": False, "type": "str"},
                "group-search-base": {"required": False, "type": "str"},
                "member-attr": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "password": {"required": False, "type": "str"},
                "password-expiry-warning": {"required": False, "type": "str",
                                            "choices": ["enable", "disable"]},
                "password-renewal": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "port": {"required": False, "type": "int"},
                "secondary-server": {"required": False, "type": "str"},
                "secure": {"required": False, "type": "str",
                           "choices": ["disable", "starttls", "ldaps"]},
                "server": {"required": False, "type": "str"},
                "source-ip": {"required": False, "type": "str"},
                "ssl-min-proto-version": {"required": False, "type": "str",
                                          "choices": ["default", "SSLv3", "TLSv1",
                                                      "TLSv1-1", "TLSv1-2"]},
                "tertiary-server": {"required": False, "type": "str"},
                "type": {"required": False, "type": "str",
                         "choices": ["simple", "anonymous", "regular"]},
                "username": {"required": False, "type": "str"}

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
