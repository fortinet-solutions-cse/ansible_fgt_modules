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
module: fortios_system_replacemsg_group
short_description: Configure replacement message groups in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and replacemsg_group category.
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
    system_replacemsg_group:
        description:
            - Configure replacement message groups.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            admin:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            alertmail:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            auth:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            comment:
                description:
                    - Comment.
            custom-message:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            device-detection-portal:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            ec:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            fortiguard-wf:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            ftp:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            group-type:
                description:
                    - Group type.
                choices:
                    - default
                    - utm
                    - auth
                    - ec
            http:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            icap:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            mail:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            nac-quar:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            name:
                description:
                    - Group name.
                required: true
            nntp:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            spam:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            sslvpn:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            traffic-quota:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            utm:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
                        required: true
            webproxy:
                description:
                    - Replacement message table entries.
                suboptions:
                    buffer:
                        description:
                            - Message string.
                    format:
                        description:
                            - Format flag.
                        choices:
                            - none
                            - text
                            - html
                            - wml
                    header:
                        description:
                            - Header flag.
                        choices:
                            - none
                            - http
                            - 8bit
                    msg-type:
                        description:
                            - Message type.
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
  - name: Configure replacement message groups.
    fortios_system_replacemsg_group:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_replacemsg_group:
        state: "present"
        admin:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        alertmail:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        auth:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        comment: "Comment."
        custom-message:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        device-detection-portal:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        ec:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        fortiguard-wf:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        ftp:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        group-type: "default"
        http:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        icap:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        mail:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        nac-quar:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        name: "default_name_65"
        nntp:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        spam:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        sslvpn:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        traffic-quota:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        utm:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
        webproxy:
         -
            buffer: "<your_own_value>"
            format: "none"
            header: "none"
            msg-type: "<your_own_value>"
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


def filter_system_replacemsg_group_data(json):
    option_list = ['admin', 'alertmail', 'auth',
                   'comment', 'custom-message', 'device-detection-portal',
                   'ec', 'fortiguard-wf', 'ftp',
                   'group-type', 'http', 'icap',
                   'mail', 'nac-quar', 'name',
                   'nntp', 'spam', 'sslvpn',
                   'traffic-quota', 'utm', 'webproxy']
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


def system_replacemsg_group(data, fos):
    vdom = data['vdom']
    system_replacemsg_group_data = data['system_replacemsg_group']
    flattened_data = flatten_multilists_attributes(system_replacemsg_group_data)
    filtered_data = filter_system_replacemsg_group_data(flattened_data)
    if system_replacemsg_group_data['state'] == "present":
        return fos.set('system',
                       'replacemsg-group',
                       data=filtered_data,
                       vdom=vdom)

    elif system_replacemsg_group_data['state'] == "absent":
        return fos.delete('system',
                          'replacemsg-group',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    if data['system_replacemsg_group']:
        resp = system_replacemsg_group(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_replacemsg_group": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "admin": {"required": False, "type": "list",
                          "options": {
                              "buffer": {"required": False, "type": "str"},
                              "format": {"required": False, "type": "str",
                                         "choices": ["none", "text", "html",
                                                     "wml"]},
                              "header": {"required": False, "type": "str",
                                         "choices": ["none", "http", "8bit"]},
                              "msg-type": {"required": True, "type": "str"}
                          }},
                "alertmail": {"required": False, "type": "list",
                              "options": {
                                  "buffer": {"required": False, "type": "str"},
                                  "format": {"required": False, "type": "str",
                                             "choices": ["none", "text", "html",
                                                         "wml"]},
                                  "header": {"required": False, "type": "str",
                                             "choices": ["none", "http", "8bit"]},
                                  "msg-type": {"required": True, "type": "str"}
                              }},
                "auth": {"required": False, "type": "list",
                         "options": {
                             "buffer": {"required": False, "type": "str"},
                             "format": {"required": False, "type": "str",
                                        "choices": ["none", "text", "html",
                                                    "wml"]},
                             "header": {"required": False, "type": "str",
                                        "choices": ["none", "http", "8bit"]},
                             "msg-type": {"required": True, "type": "str"}
                         }},
                "comment": {"required": False, "type": "str"},
                "custom-message": {"required": False, "type": "list",
                                   "options": {
                                       "buffer": {"required": False, "type": "str"},
                                       "format": {"required": False, "type": "str",
                                                  "choices": ["none", "text", "html",
                                                              "wml"]},
                                       "header": {"required": False, "type": "str",
                                                  "choices": ["none", "http", "8bit"]},
                                       "msg-type": {"required": True, "type": "str"}
                                   }},
                "device-detection-portal": {"required": False, "type": "list",
                                            "options": {
                                                "buffer": {"required": False, "type": "str"},
                                                "format": {"required": False, "type": "str",
                                                           "choices": ["none", "text", "html",
                                                                       "wml"]},
                                                "header": {"required": False, "type": "str",
                                                           "choices": ["none", "http", "8bit"]},
                                                "msg-type": {"required": True, "type": "str"}
                                            }},
                "ec": {"required": False, "type": "list",
                       "options": {
                           "buffer": {"required": False, "type": "str"},
                           "format": {"required": False, "type": "str",
                                      "choices": ["none", "text", "html",
                                                  "wml"]},
                           "header": {"required": False, "type": "str",
                                      "choices": ["none", "http", "8bit"]},
                           "msg-type": {"required": True, "type": "str"}
                       }},
                "fortiguard-wf": {"required": False, "type": "list",
                                  "options": {
                                      "buffer": {"required": False, "type": "str"},
                                      "format": {"required": False, "type": "str",
                                                 "choices": ["none", "text", "html",
                                                             "wml"]},
                                      "header": {"required": False, "type": "str",
                                                 "choices": ["none", "http", "8bit"]},
                                      "msg-type": {"required": True, "type": "str"}
                                  }},
                "ftp": {"required": False, "type": "list",
                        "options": {
                            "buffer": {"required": False, "type": "str"},
                            "format": {"required": False, "type": "str",
                                       "choices": ["none", "text", "html",
                                                   "wml"]},
                            "header": {"required": False, "type": "str",
                                       "choices": ["none", "http", "8bit"]},
                            "msg-type": {"required": True, "type": "str"}
                        }},
                "group-type": {"required": False, "type": "str",
                               "choices": ["default", "utm", "auth",
                                           "ec"]},
                "http": {"required": False, "type": "list",
                         "options": {
                             "buffer": {"required": False, "type": "str"},
                             "format": {"required": False, "type": "str",
                                        "choices": ["none", "text", "html",
                                                    "wml"]},
                             "header": {"required": False, "type": "str",
                                        "choices": ["none", "http", "8bit"]},
                             "msg-type": {"required": True, "type": "str"}
                         }},
                "icap": {"required": False, "type": "list",
                         "options": {
                             "buffer": {"required": False, "type": "str"},
                             "format": {"required": False, "type": "str",
                                        "choices": ["none", "text", "html",
                                                    "wml"]},
                             "header": {"required": False, "type": "str",
                                        "choices": ["none", "http", "8bit"]},
                             "msg-type": {"required": True, "type": "str"}
                         }},
                "mail": {"required": False, "type": "list",
                         "options": {
                             "buffer": {"required": False, "type": "str"},
                             "format": {"required": False, "type": "str",
                                        "choices": ["none", "text", "html",
                                                    "wml"]},
                             "header": {"required": False, "type": "str",
                                        "choices": ["none", "http", "8bit"]},
                             "msg-type": {"required": True, "type": "str"}
                         }},
                "nac-quar": {"required": False, "type": "list",
                             "options": {
                                 "buffer": {"required": False, "type": "str"},
                                 "format": {"required": False, "type": "str",
                                            "choices": ["none", "text", "html",
                                                        "wml"]},
                                 "header": {"required": False, "type": "str",
                                            "choices": ["none", "http", "8bit"]},
                                 "msg-type": {"required": True, "type": "str"}
                             }},
                "name": {"required": True, "type": "str"},
                "nntp": {"required": False, "type": "list",
                         "options": {
                             "buffer": {"required": False, "type": "str"},
                             "format": {"required": False, "type": "str",
                                        "choices": ["none", "text", "html",
                                                    "wml"]},
                             "header": {"required": False, "type": "str",
                                        "choices": ["none", "http", "8bit"]},
                             "msg-type": {"required": True, "type": "str"}
                         }},
                "spam": {"required": False, "type": "list",
                         "options": {
                             "buffer": {"required": False, "type": "str"},
                             "format": {"required": False, "type": "str",
                                        "choices": ["none", "text", "html",
                                                    "wml"]},
                             "header": {"required": False, "type": "str",
                                        "choices": ["none", "http", "8bit"]},
                             "msg-type": {"required": True, "type": "str"}
                         }},
                "sslvpn": {"required": False, "type": "list",
                           "options": {
                               "buffer": {"required": False, "type": "str"},
                               "format": {"required": False, "type": "str",
                                          "choices": ["none", "text", "html",
                                                      "wml"]},
                               "header": {"required": False, "type": "str",
                                          "choices": ["none", "http", "8bit"]},
                               "msg-type": {"required": True, "type": "str"}
                           }},
                "traffic-quota": {"required": False, "type": "list",
                                  "options": {
                                      "buffer": {"required": False, "type": "str"},
                                      "format": {"required": False, "type": "str",
                                                 "choices": ["none", "text", "html",
                                                             "wml"]},
                                      "header": {"required": False, "type": "str",
                                                 "choices": ["none", "http", "8bit"]},
                                      "msg-type": {"required": True, "type": "str"}
                                  }},
                "utm": {"required": False, "type": "list",
                        "options": {
                            "buffer": {"required": False, "type": "str"},
                            "format": {"required": False, "type": "str",
                                       "choices": ["none", "text", "html",
                                                   "wml"]},
                            "header": {"required": False, "type": "str",
                                       "choices": ["none", "http", "8bit"]},
                            "msg-type": {"required": True, "type": "str"}
                        }},
                "webproxy": {"required": False, "type": "list",
                             "options": {
                                 "buffer": {"required": False, "type": "str"},
                                 "format": {"required": False, "type": "str",
                                            "choices": ["none", "text", "html",
                                                        "wml"]},
                                 "header": {"required": False, "type": "str",
                                            "choices": ["none", "http", "8bit"]},
                                 "msg-type": {"required": True, "type": "str"}
                             }}

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

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
