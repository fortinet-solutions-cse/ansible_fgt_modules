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
module: fortios_vpn_ssl_web_host_check_software
short_description: SSL-VPN host check software in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify vpn_ssl_web feature and host_check_software category.
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
    vpn_ssl_web_host_check_software:
        description:
            - SSL-VPN host check software.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            check-item-list:
                description:
                    - Check item list.
                suboptions:
                    action:
                        description:
                            - Action.
                        choices:
                            - require
                            - deny
                    id:
                        description:
                            - ID (0 - 4294967295).
                        required: true
                    md5s:
                        description:
                            - MD5 checksum.
                        suboptions:
                            id:
                                description:
                                    - Hex string of MD5 checksum.
                                required: true
                    target:
                        description:
                            - Target.
                    type:
                        description:
                            - Type.
                        choices:
                            - file
                            - registry
                            - process
                    version:
                        description:
                            - Version.
            guid:
                description:
                    - Globally unique ID.
            name:
                description:
                    - Name.
                required: true
            os-type:
                description:
                    - OS type.
                choices:
                    - windows
                    - macos
            type:
                description:
                    - Type.
                choices:
                    - av
                    - fw
            version:
                description:
                    - Version.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: SSL-VPN host check software.
    fortios_vpn_ssl_web_host_check_software:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      vpn_ssl_web_host_check_software:
        state: "present"
        check-item-list:
         -
            action: "require"
            id:  "5"
            md5s:
             -
                id:  "7"
            target: "<your_own_value>"
            type: "file"
            version: "<your_own_value>"
        guid: "<your_own_value>"
        name: "default_name_12"
        os-type: "windows"
        type: "av"
        version: "<your_own_value>"
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


def filter_vpn_ssl_web_host_check_software_data(json):
    option_list = ['check-item-list', 'guid', 'name',
                   'os-type', 'type', 'version']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def vpn_ssl_web_host_check_software(data, fos):
    vdom = data['vdom']
    vpn_ssl_web_host_check_software_data = data['vpn_ssl_web_host_check_software']
    filtered_data = filter_vpn_ssl_web_host_check_software_data(vpn_ssl_web_host_check_software_data)

    if vpn_ssl_web_host_check_software_data['state'] == "present":
        return fos.set('vpn.ssl.web',
                       'host-check-software',
                       data=filtered_data,
                       vdom=vdom)

    elif vpn_ssl_web_host_check_software_data['state'] == "absent":
        return fos.delete('vpn.ssl.web',
                          'host-check-software',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_vpn_ssl_web(data, fos):
    login(data, fos)

    if data['vpn_ssl_web_host_check_software']:
        resp = vpn_ssl_web_host_check_software(data, fos)

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
        "vpn_ssl_web_host_check_software": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "check-item-list": {"required": False, "type": "list",
                                    "options": {
                                        "action": {"required": False, "type": "str",
                                                   "choices": ["require", "deny"]},
                                        "id": {"required": True, "type": "int"},
                                        "md5s": {"required": False, "type": "list",
                                                 "options": {
                                                     "id": {"required": True, "type": "str"}
                                                 }},
                                        "target": {"required": False, "type": "str"},
                                        "type": {"required": False, "type": "str",
                                                 "choices": ["file", "registry", "process"]},
                                        "version": {"required": False, "type": "str"}
                                    }},
                "guid": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "os-type": {"required": False, "type": "str",
                            "choices": ["windows", "macos"]},
                "type": {"required": False, "type": "str",
                         "choices": ["av", "fw"]},
                "version": {"required": False, "type": "str"}

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

    is_error, has_changed, result = fortios_vpn_ssl_web(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
