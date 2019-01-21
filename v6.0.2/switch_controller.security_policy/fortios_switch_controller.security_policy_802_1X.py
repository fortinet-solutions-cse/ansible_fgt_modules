#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
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
module: fortios_switch_controller.security_policy_802_1X
short_description: Configure 802.1x MAC Authentication Bypass (MAB) policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure switch_controller.security_policy feature and 802_1X category.
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
        default: false
    switch_controller.security_policy_802_1X:
        description:
            - Configure 802.1x MAC Authentication Bypass (MAB) policies.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            auth-fail-vlan:
                description:
                    - Enable to allow limited access to clients that cannot authenticate.
                choices:
                    - disable
                    - enable
            auth-fail-vlan-id:
                description:
                    - VLAN ID on which authentication failed. Source system.interface.name.
            auth-fail-vlanid:
                description:
                    - VLAN ID on which authentication failed.
            eap-passthru:
                description:
                    - Enable/disable EAP pass-through mode, allowing protocols (such as LLDP) to pass through ports for more flexible authentication.
                choices:
                    - disable
                    - enable
            guest-auth-delay:
                description:
                    - Guest authentication delay (1 - 900  sec, default = 30).
            guest-vlan:
                description:
                    - Enable the guest VLAN feature to allow limited access to non-802.1X-compliant clients.
                choices:
                    - disable
                    - enable
            guest-vlan-id:
                description:
                    - Guest VLAN name. Source system.interface.name.
            guest-vlanid:
                description:
                    - Guest VLAN ID.
            mac-auth-bypass:
                description:
                    - Enable/disable MAB for this policy.
                choices:
                    - disable
                    - enable
            name:
                description:
                    - Policy name.
                required: true
            open-auth:
                description:
                    - Enable/disable open authentication for this policy.
                choices:
                    - disable
                    - enable
            policy-type:
                description:
                    - Policy type.
                choices:
                    - 802.1X
            radius-timeout-overwrite:
                description:
                    - Enable to override the global RADIUS session timeout.
                choices:
                    - disable
                    - enable
            security-mode:
                description:
                    - Port or MAC based 802.1X security mode.
                choices:
                    - 802.1X
                    - 802.1X-mac-based
            user-group:
                description:
                    - Name of user-group to assign to this MAC Authentication Bypass (MAB) policy.
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
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
  - name: Configure 802.1x MAC Authentication Bypass (MAB) policies.
    fortios_switch_controller.security_policy_802_1X:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      switch_controller.security_policy_802_1X:
        state: "present"
        auth-fail-vlan: "disable"
        auth-fail-vlan-id: "<your_own_value> (source system.interface.name)"
        auth-fail-vlanid: "5"
        eap-passthru: "disable"
        guest-auth-delay: "7"
        guest-vlan: "disable"
        guest-vlan-id: "<your_own_value> (source system.interface.name)"
        guest-vlanid: "10"
        mac-auth-bypass: "disable"
        name: "default_name_12"
        open-auth: "disable"
        policy-type: "802.1X"
        radius-timeout-overwrite: "disable"
        security-mode: "802.1X"
        user-group:
         -
            name: "default_name_18 (source user.group.name)"
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


def filter_switch_controller.security_policy_802_1X_data(json):
    option_list = ['auth-fail-vlan', 'auth-fail-vlan-id', 'auth-fail-vlanid',
                   'eap-passthru', 'guest-auth-delay', 'guest-vlan',
                   'guest-vlan-id', 'guest-vlanid', 'mac-auth-bypass',
                   'name', 'open-auth', 'policy-type',
                   'radius-timeout-overwrite', 'security-mode', 'user-group']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def switch_controller.security_policy_802_1X(data, fos):
    vdom = data['vdom']
    switch_controller.security_policy_802_1X_data = data['switch_controller.security_policy_802_1X']
    filtered_data = filter_switch_controller.security_policy_802_1X_data(switch_controller.security_policy_802_1X_data)
    if switch_controller.security_policy_802_1X_data['state'] == "present":
        return fos.set('switch-controller.security-policy',
                       '802-1X',
                       data=filtered_data,
                       vdom=vdom)

    elif switch_controller.security_policy_802_1X_data['state'] == "absent":
        return fos.delete('switch-controller.security-policy',
                          '802-1X',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_switch_controller.security_policy(data, fos):
    login(data)

    methodlist = ['switch_controller.security_policy_802_1X']
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
        "https": {"required": False, "type": "bool", "default": "False"},
        "switch_controller.security_policy_802_1X": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "auth-fail-vlan": {"required": False, "type": "str",
                                   "choices": ["disable", "enable"]},
                "auth-fail-vlan-id": {"required": False, "type": "str"},
                "auth-fail-vlanid": {"required": False, "type": "int"},
                "eap-passthru": {"required": False, "type": "str",
                                 "choices": ["disable", "enable"]},
                "guest-auth-delay": {"required": False, "type": "int"},
                "guest-vlan": {"required": False, "type": "str",
                               "choices": ["disable", "enable"]},
                "guest-vlan-id": {"required": False, "type": "str"},
                "guest-vlanid": {"required": False, "type": "int"},
                "mac-auth-bypass": {"required": False, "type": "str",
                                    "choices": ["disable", "enable"]},
                "name": {"required": True, "type": "str"},
                "open-auth": {"required": False, "type": "str",
                              "choices": ["disable", "enable"]},
                "policy-type": {"required": False, "type": "str",
                                "choices": ["802.1X"]},
                "radius-timeout-overwrite": {"required": False, "type": "str",
                                             "choices": ["disable", "enable"]},
                "security-mode": {"required": False, "type": "str",
                                  "choices": ["802.1X", "802.1X-mac-based"]},
                "user-group": {"required": False, "type": "list",
                               "options": {
                                   "name": {"required": True, "type": "str"}
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

    is_error, has_changed, result = fortios_switch_controller.security_policy(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
