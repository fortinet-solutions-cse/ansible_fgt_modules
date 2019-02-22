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
module: fortios_system_vdom_property
short_description: Configure VDOM property in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and vdom_property category.
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
    system_vdom_property:
        description:
            - Configure VDOM property.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            custom-service:
                description:
                    - Maximum guaranteed number of firewall custom services.
            description:
                description:
                    - Description.
            dialup-tunnel:
                description:
                    - Maximum guaranteed number of dial-up tunnels.
            firewall-address:
                description:
                    - Maximum guaranteed number of firewall addresses.
            firewall-addrgrp:
                description:
                    - Maximum guaranteed number of firewall address groups.
            firewall-policy:
                description:
                    - Maximum guaranteed number of firewall policies.
            ipsec-phase1:
                description:
                    - Maximum guaranteed number of VPN IPsec phase 1 tunnels.
            ipsec-phase1-interface:
                description:
                    - Maximum guaranteed number of VPN IPsec phase1 interface tunnels.
            ipsec-phase2:
                description:
                    - Maximum guaranteed number of VPN IPsec phase 2 tunnels.
            ipsec-phase2-interface:
                description:
                    - Maximum guaranteed number of VPN IPsec phase2 interface tunnels.
            log-disk-quota:
                description:
                    - Log disk quota in MB (range depends on how much disk space is available).
            name:
                description:
                    - VDOM name. Source system.vdom.name.
                required: true
            onetime-schedule:
                description:
                    - Maximum guaranteed number of firewall one-time schedules.
            proxy:
                description:
                    - Maximum guaranteed number of concurrent proxy users.
            recurring-schedule:
                description:
                    - Maximum guaranteed number of firewall recurring schedules.
            service-group:
                description:
                    - Maximum guaranteed number of firewall service groups.
            session:
                description:
                    - Maximum guaranteed number of sessions.
            snmp-index:
                description:
                    - Permanent SNMP Index of the virtual domain (0 - 4294967295).
            sslvpn:
                description:
                    - Maximum guaranteed number of SSL-VPNs.
            user:
                description:
                    - Maximum guaranteed number of local users.
            user-group:
                description:
                    - Maximum guaranteed number of user groups.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure VDOM property.
    fortios_system_vdom_property:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_vdom_property:
        state: "present"
        custom-service: "<your_own_value>"
        description: "<your_own_value>"
        dialup-tunnel: "<your_own_value>"
        firewall-address: "<your_own_value>"
        firewall-addrgrp: "<your_own_value>"
        firewall-policy: "<your_own_value>"
        ipsec-phase1: "<your_own_value>"
        ipsec-phase1-interface: "<your_own_value>"
        ipsec-phase2: "<your_own_value>"
        ipsec-phase2-interface: "<your_own_value>"
        log-disk-quota: "<your_own_value>"
        name: "default_name_14 (source system.vdom.name)"
        onetime-schedule: "<your_own_value>"
        proxy: "<your_own_value>"
        recurring-schedule: "<your_own_value>"
        service-group: "<your_own_value>"
        session: "<your_own_value>"
        snmp-index: "20"
        sslvpn: "<your_own_value>"
        user: "<your_own_value>"
        user-group: "<your_own_value>"
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


def filter_system_vdom_property_data(json):
    option_list = ['custom-service', 'description', 'dialup-tunnel',
                   'firewall-address', 'firewall-addrgrp', 'firewall-policy',
                   'ipsec-phase1', 'ipsec-phase1-interface', 'ipsec-phase2',
                   'ipsec-phase2-interface', 'log-disk-quota', 'name',
                   'onetime-schedule', 'proxy', 'recurring-schedule',
                   'service-group', 'session', 'snmp-index',
                   'sslvpn', 'user', 'user-group']
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


def system_vdom_property(data, fos):
    vdom = data['vdom']
    system_vdom_property_data = data['system_vdom_property']
    flattened_data = flatten_multilists_attributes(system_vdom_property_data)
    filtered_data = filter_system_vdom_property_data(flattened_data)
    if system_vdom_property_data['state'] == "present":
        return fos.set('system',
                       'vdom-property',
                       data=filtered_data,
                       vdom=vdom)

    elif system_vdom_property_data['state'] == "absent":
        return fos.delete('system',
                          'vdom-property',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    if data['system_vdom_property']:
        resp = system_vdom_property(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_vdom_property": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "custom-service": {"required": False, "type": "str"},
                "description": {"required": False, "type": "str"},
                "dialup-tunnel": {"required": False, "type": "str"},
                "firewall-address": {"required": False, "type": "str"},
                "firewall-addrgrp": {"required": False, "type": "str"},
                "firewall-policy": {"required": False, "type": "str"},
                "ipsec-phase1": {"required": False, "type": "str"},
                "ipsec-phase1-interface": {"required": False, "type": "str"},
                "ipsec-phase2": {"required": False, "type": "str"},
                "ipsec-phase2-interface": {"required": False, "type": "str"},
                "log-disk-quota": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "onetime-schedule": {"required": False, "type": "str"},
                "proxy": {"required": False, "type": "str"},
                "recurring-schedule": {"required": False, "type": "str"},
                "service-group": {"required": False, "type": "str"},
                "session": {"required": False, "type": "str"},
                "snmp-index": {"required": False, "type": "int"},
                "sslvpn": {"required": False, "type": "str"},
                "user": {"required": False, "type": "str"},
                "user-group": {"required": False, "type": "str"}

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
