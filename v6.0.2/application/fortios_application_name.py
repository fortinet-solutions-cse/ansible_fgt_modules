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
module: fortios_application_name
short_description: Configure application signatures in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify application feature and name category.
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
    application_name:
        description:
            - Configure application signatures.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            behavior:
                description:
                    - Application behavior.
            category:
                description:
                    - Application category ID.
            id:
                description:
                    - Application ID.
            metadata:
                description:
                    - Meta data.
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                    metaid:
                        description:
                            - Meta ID.
                    valueid:
                        description:
                            - Value ID.
            name:
                description:
                    - Application name.
                required: true
            parameter:
                description:
                    - Application parameter name.
            popularity:
                description:
                    - Application popularity.
            protocol:
                description:
                    - Application protocol.
            risk:
                description:
                    - Application risk.
            sub-category:
                description:
                    - Application sub-category ID.
            technology:
                description:
                    - Application technology.
            vendor:
                description:
                    - Application vendor.
            weight:
                description:
                    - Application weight.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure application signatures.
    fortios_application_name:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      application_name:
        state: "present"
        behavior: "<your_own_value>"
        category: "4"
        id:  "5"
        metadata:
         -
            id:  "7"
            metaid: "8"
            valueid: "9"
        name: "default_name_10"
        parameter: "<your_own_value>"
        popularity: "12"
        protocol: "<your_own_value>"
        risk: "14"
        sub-category: "15"
        technology: "<your_own_value>"
        vendor: "<your_own_value>"
        weight: "18"
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


def filter_application_name_data(json):
    option_list = ['behavior', 'category', 'id',
                   'metadata', 'name', 'parameter',
                   'popularity', 'protocol', 'risk',
                   'sub-category', 'technology', 'vendor',
                   'weight']
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


def application_name(data, fos):
    vdom = data['vdom']
    application_name_data = data['application_name']
    flattened_data = flatten_multilists_attributes(application_name_data)
    filtered_data = filter_application_name_data(flattened_data)
    if application_name_data['state'] == "present":
        return fos.set('application',
                       'name',
                       data=filtered_data,
                       vdom=vdom)

    elif application_name_data['state'] == "absent":
        return fos.delete('application',
                          'name',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_application(data, fos):
    login(data, fos)

    if data['application_name']:
        resp = application_name(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "application_name": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "behavior": {"required": False, "type": "str"},
                "category": {"required": False, "type": "int"},
                "id": {"required": False, "type": "int"},
                "metadata": {"required": False, "type": "list",
                             "options": {
                                 "id": {"required": True, "type": "int"},
                                 "metaid": {"required": False, "type": "int"},
                                 "valueid": {"required": False, "type": "int"}
                             }},
                "name": {"required": True, "type": "str"},
                "parameter": {"required": False, "type": "str"},
                "popularity": {"required": False, "type": "int"},
                "protocol": {"required": False, "type": "str"},
                "risk": {"required": False, "type": "int"},
                "sub-category": {"required": False, "type": "int"},
                "technology": {"required": False, "type": "str"},
                "vendor": {"required": False, "type": "str"},
                "weight": {"required": False, "type": "int"}

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

    is_error, has_changed, result = fortios_application(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
