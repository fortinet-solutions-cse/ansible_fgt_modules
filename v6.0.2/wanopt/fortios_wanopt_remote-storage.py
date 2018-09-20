#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.basic import AnsibleModule
# Copyright 2018 Fortinet, Inc.
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
module: fortios_wanopt_remote-storage
short_description: Configure a remote cache device as Web cache storage.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wanopt feature and remote-storage category.
      Examples includes all options and need to be adjusted to datasources before usage.
      Tested with FOS: v6.0.2
version_added: "2.6"
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
        default: "root"
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
    wanopt_remote-storage:
        description:
            - Configure a remote cache device as Web cache storage.
        default: null
        suboptions:
            local-cache-id:
                description:
                    - ID that this device uses to connect to the remote device.
            remote-cache-id:
                description:
                    - ID of the remote device to which the device connects.
            remote-cache-ip:
                description:
                    - IP address of the remote device to which the device connects.
            status:
                description:
                    - Enable/disable using remote device as Web cache storage.
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
  - name: Configure a remote cache device as Web cache storage.
    fortios_wanopt_remote-storage:
      host:  "{{  host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      wanopt_remote-storage:
        state: "present"
        local-cache-id: "<your_own_value>"
        remote-cache-id: "<your_own_value>"
        remote-cache-ip: "<your_own_value>"
        status: "disable"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: string
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: string
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: string
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: string
  sample: "key1"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: string
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: string
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: string
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: string
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: string
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: string
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: string
  sample: "v5.6.3"

'''

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


def filter_wanopt_remote-storage_data(json):
    option_list = ['local-cache-id', 'remote-cache-id', 'remote-cache-ip',
                   'status']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def wanopt_remote-storage(data, fos):
    vdom = data['vdom']
    wanopt_remote-storage_data = data['wanopt_remote-storage']
    filtered_data = filter_wanopt_remote - \
        storage_data(wanopt_remote-storage_data)

    if wanopt_remote-storage_data['state'] == "present":
        return fos.set('wanopt',
                       'remote-storage',
                       data=filtered_data,
                       vdom=vdom)

    elif wanopt_remote-storage_data['state'] == "absent":
        return fos.delete('wanopt',
                          'remote-storage',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_wanopt(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    fos.https('off')
    fos.login(host, username, password)

    methodlist = ['wanopt_remote-storage']
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
        "https": {"required": False, "type": "bool", "default": "True"},
        "wanopt_remote-storage": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str"},
                "local-cache-id": {"required": False, "type": "str"},
                "remote-cache-id": {"required": False, "type": "str"},
                "remote-cache-ip": {"required": False, "type": "ipv4-address-any"},
                "status": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_wanopt(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
