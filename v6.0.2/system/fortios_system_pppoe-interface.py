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
module: fortios_system_pppoe-interface
short_description: Configure the PPPoE interfaces.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system feature and pppoe-interface category.
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
    system_pppoe-interface:
        description:
            - Configure the PPPoE interfaces.
        default: null
        suboptions:
            ac-name:
                description:
                    - PPPoE AC name.
            auth-type:
                description:
                    - PPP authentication type to use.
                choices:
                    - auto
                    - pap
                    - chap
                    - mschapv1
                    - mschapv2
            device:
                description:
                    - Name for the physical interface. Source: system.interface.name.
            dial-on-demand:
                description:
                    - Enable/disable dial on demand to dial the PPPoE interface when packets are routed to the PPPoE interface.
                choices:
                    - enable
                    - disable
            disc-retry-timeout:
                description:
                    - PPPoE discovery init timeout value in (0-4294967295 sec).
            idle-timeout:
                description:
                    - PPPoE auto disconnect after idle timeout (0-4294967295 sec).
            ipunnumbered:
                description:
                    - PPPoE unnumbered IP.
            ipv6:
                description:
                    - Enable/disable IPv6 Control Protocol (IPv6CP).
                choices:
                    - enable
                    - disable
            lcp-echo-interval:
                description:
                    - PPPoE LCP echo interval in (0-4294967295 sec, default = 5).
            lcp-max-echo-fails:
                description:
                    - Maximum missed LCP echo messages before disconnect (0-4294967295, default = 3).
            name:
                description:
                    - Name of the PPPoE interface.
                required: true
            padt-retry-timeout:
                description:
                    - PPPoE terminate timeout value in (0-4294967295 sec).
            password:
                description:
                    - Enter the password.
            pppoe-unnumbered-negotiate:
                description:
                    - Enable/disable PPPoE unnumbered negotiation.
                choices:
                    - enable
                    - disable
            service-name:
                description:
                    - PPPoE service name.
            username:
                description:
                    - User name.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure the PPPoE interfaces.
    fortios_system_pppoe-interface:
      host:  "{{  host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      system_pppoe-interface:
        state: "present"
        ac-name: "<your_own_value>"
        auth-type: "auto"
        device: "<your_own_value> (source: system.interface.name)"
        dial-on-demand: "enable"
        disc-retry-timeout: "7"
        idle-timeout: "8"
        ipunnumbered: "<your_own_value>"
        ipv6: "enable"
        lcp-echo-interval: "11"
        lcp-max-echo-fails: "12"
        name: "default_name_13"
        padt-retry-timeout: "14"
        password: "<your_own_value>"
        pppoe-unnumbered-negotiate: "enable"
        service-name: "<your_own_value>"
        username: "<your_own_value>"
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


def filter_system_pppoe-interface_data(json):
    option_list = ['ac-name', 'auth-type', 'device',
                   'dial-on-demand', 'disc-retry-timeout', 'idle-timeout',
                   'ipunnumbered', 'ipv6', 'lcp-echo-interval',
                   'lcp-max-echo-fails', 'name', 'padt-retry-timeout',
                   'password', 'pppoe-unnumbered-negotiate', 'service-name',
                   'username']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_pppoe-interface(data, fos):
    vdom = data['vdom']
    system_pppoe-interface_data = data['system_pppoe-interface']
    filtered_data = filter_system_pppoe - \
        interface_data(system_pppoe-interface_data)

    if system_pppoe-interface_data['state'] == "present":
        return fos.set('system',
                       'pppoe-interface',
                       data=filtered_data,
                       vdom=vdom)

    elif system_pppoe-interface_data['state'] == "absent":
        return fos.delete('system',
                          'pppoe-interface',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_system(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    fos.https('off')
    fos.login(host, username, password)

    methodlist = ['system_pppoe-interface']
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
        "system_pppoe-interface": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str"},
                "ac-name": {"required": False, "type": "str"},
                "auth-type": {"required": False, "type": "str",
                              "choices": ["auto", "pap", "chap",
                                          "mschapv1", "mschapv2"]},
                "device": {"required": False, "type": "str"},
                "dial-on-demand": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "disc-retry-timeout": {"required": False, "type": "int"},
                "idle-timeout": {"required": False, "type": "int"},
                "ipunnumbered": {"required": False, "type": "ipv4-address"},
                "ipv6": {"required": False, "type": "str",
                         "choices": ["enable", "disable"]},
                "lcp-echo-interval": {"required": False, "type": "int"},
                "lcp-max-echo-fails": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "padt-retry-timeout": {"required": False, "type": "int"},
                "password": {"required": False, "type": "password"},
                "pppoe-unnumbered-negotiate": {"required": False, "type": "str",
                                               "choices": ["enable", "disable"]},
                "service-name": {"required": False, "type": "str"},
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

    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
