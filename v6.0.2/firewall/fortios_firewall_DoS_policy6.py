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
module: fortios_firewall_DoS_policy6
short_description: Configure IPv6 DoS policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure firewall feature and DoS_policy6 category.
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
    firewall_DoS_policy6:
        description:
            - Configure IPv6 DoS policies.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            anomaly:
                description:
                    - Anomaly name.
                suboptions:
                    action:
                        description:
                            - Action taken when the threshold is reached.
                        choices:
                            - pass
                            - block
                    log:
                        description:
                            - Enable/disable anomaly logging.
                        choices:
                            - enable
                            - disable
                    name:
                        description:
                            - Anomaly name.
                        required: true
                    quarantine:
                        description:
                            - Quarantine method.
                        choices:
                            - none
                            - attacker
                    quarantine-expiry:
                        description:
                            - Duration of quarantine. (Format ###d##h##m, minimum 1m, maximum 364d23h59m, default = 5m). Requires quarantine set to attacker.
                    quarantine-log:
                        description:
                            - Enable/disable quarantine logging.
                        choices:
                            - disable
                            - enable
                    status:
                        description:
                            - Enable/disable this anomaly.
                        choices:
                            - disable
                            - enable
                    threshold:
                        description:
                            - Anomaly threshold. Number of detected instances per minute that triggers the anomaly action.
                    threshold(default):
                        description:
                            - Number of detected instances per minute which triggers action (1 - 2147483647, default = 1000). Note that each anomaly has a
                               different threshold value assigned to it.
            comments:
                description:
                    - Comment.
            dstaddr:
                description:
                    - Destination address name from available addresses.
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
            interface:
                description:
                    - Incoming interface name from available interfaces. Source system.zone.name system.interface.name.
            policyid:
                description:
                    - Policy ID.
                required: true
            service:
                description:
                    - Service object from available options.
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
            srcaddr:
                description:
                    - Source address name from available addresses.
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
            status:
                description:
                    - Enable/disable this policy.
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
  - name: Configure IPv6 DoS policies.
    fortios_firewall_DoS_policy6:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      firewall_DoS_policy6:
        state: "present"
        anomaly:
         -
            action: "pass"
            log: "enable"
            name: "default_name_6"
            quarantine: "none"
            quarantine-expiry: "<your_own_value>"
            quarantine-log: "disable"
            status: "disable"
            threshold: "11"
            threshold(default): "12"
        comments: "<your_own_value>"
        dstaddr:
         -
            name: "default_name_15 (source firewall.address6.name firewall.addrgrp6.name)"
        interface: "<your_own_value> (source system.zone.name system.interface.name)"
        policyid: "17"
        service:
         -
            name: "default_name_19 (source firewall.service.custom.name firewall.service.group.name)"
        srcaddr:
         -
            name: "default_name_21 (source firewall.address6.name firewall.addrgrp6.name)"
        status: "enable"
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


def filter_firewall_DoS_policy6_data(json):
    option_list = ['anomaly', 'comments', 'dstaddr',
                   'interface', 'policyid', 'service',
                   'srcaddr', 'status']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def firewall_DoS_policy6(data, fos):
    vdom = data['vdom']
    firewall_DoS_policy6_data = data['firewall_DoS_policy6']
    filtered_data = filter_firewall_DoS_policy6_data(firewall_DoS_policy6_data)
    if firewall_DoS_policy6_data['state'] == "present":
        return fos.set('firewall',
                       'DoS-policy6',
                       data=filtered_data,
                       vdom=vdom)

    elif firewall_DoS_policy6_data['state'] == "absent":
        return fos.delete('firewall',
                          'DoS-policy6',
                          mkey=filtered_data['policyid'],
                          vdom=vdom)


def fortios_firewall(data, fos):
    login(data)

    methodlist = ['firewall_DoS_policy6']
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
        "firewall_DoS_policy6": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "anomaly": {"required": False, "type": "list",
                            "options": {
                                "action": {"required": False, "type": "str",
                                           "choices": ["pass", "block"]},
                                "log": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                                "name": {"required": True, "type": "str"},
                                "quarantine": {"required": False, "type": "str",
                                               "choices": ["none", "attacker"]},
                                "quarantine-expiry": {"required": False, "type": "str"},
                                "quarantine-log": {"required": False, "type": "str",
                                                   "choices": ["disable", "enable"]},
                                "status": {"required": False, "type": "str",
                                           "choices": ["disable", "enable"]},
                                "threshold": {"required": False, "type": "int"},
                                "threshold(default)": {"required": False, "type": "int"}
                            }},
                "comments": {"required": False, "type": "str"},
                "dstaddr": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "interface": {"required": False, "type": "str"},
                "policyid": {"required": True, "type": "int"},
                "service": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "srcaddr": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "status": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_firewall(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
