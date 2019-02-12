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
module: fortios_certificate_ca
short_description: CA certificate in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure certificate feature and ca category.
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
        default: true
    certificate_ca:
        description:
            - CA certificate.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            auto-update-days:
                description:
                    - Number of days to wait before requesting an updated CA certificate (0 - 4294967295, 0 = disabled).
            auto-update-days-warning:
                description:
                    - Number of days before an expiry-warning message is generated (0 - 4294967295, 0 = disabled).
            ca:
                description:
                    - CA certificate as a PEM file.
            last-updated:
                description:
                    - Time at which CA was last updated.
            name:
                description:
                    - Name.
                required: true
            range:
                description:
                    - Either global or VDOM IP address range for the CA certificate.
                choices:
                    - global
                    - vdom
            scep-url:
                description:
                    - URL of the SCEP server.
            source:
                description:
                    - CA certificate source type.
                choices:
                    - factory
                    - user
                    - bundle
                    - fortiguard
            source-ip:
                description:
                    - Source IP address for communications to the SCEP server.
            trusted:
                description:
                    - Enable/disable as a trusted CA.
                choices:
                    - enable
                    - disable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: CA certificate.
    fortios_certificate_ca:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      certificate_ca:
        state: "present"
        auto-update-days: "3"
        auto-update-days-warning: "4"
        ca: "<your_own_value>"
        last-updated: "6"
        name: "default_name_7"
        range: "global"
        scep-url: "<your_own_value>"
        source: "factory"
        source-ip: "84.230.14.43"
        trusted: "enable"
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


def filter_certificate_ca_data(json):
    option_list = ['auto-update-days', 'auto-update-days-warning', 'ca',
                   'last-updated', 'name', 'range',
                   'scep-url', 'source', 'source-ip',
                   'trusted']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def certificate_ca(data, fos):
    vdom = data['vdom']
    certificate_ca_data = data['certificate_ca']
    filtered_data = filter_certificate_ca_data(certificate_ca_data)
    if certificate_ca_data['state'] == "present":
        return fos.set('certificate',
                       'ca',
                       data=filtered_data,
                       vdom=vdom)

    elif certificate_ca_data['state'] == "absent":
        return fos.delete('certificate',
                          'ca',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_certificate(data, fos):
    login(data)

    methodlist = ['certificate_ca']
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
        "certificate_ca": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "auto-update-days": {"required": False, "type": "int"},
                "auto-update-days-warning": {"required": False, "type": "int"},
                "ca": {"required": False, "type": "str"},
                "last-updated": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "range": {"required": False, "type": "str",
                          "choices": ["global", "vdom"]},
                "scep-url": {"required": False, "type": "str"},
                "source": {"required": False, "type": "str",
                           "choices": ["factory", "user", "bundle",
                                       "fortiguard"]},
                "source-ip": {"required": False, "type": "str"},
                "trusted": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]}

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

    is_error, has_changed, result = fortios_certificate(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
