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
module: fortios_system_snmp_user
short_description: SNMP user configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system_snmp feature and user category.
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
    system_snmp_user:
        description:
            - SNMP user configuration.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            auth-proto:
                description:
                    - Authentication protocol.
                choices:
                    - md5
                    - sha
            auth-pwd:
                description:
                    - Password for authentication protocol.
            events:
                description:
                    - SNMP notifications (traps) to send.
                choices:
                    - cpu-high
                    - mem-low
                    - log-full
                    - intf-ip
                    - vpn-tun-up
                    - vpn-tun-down
                    - ha-switch
                    - ha-hb-failure
                    - ips-signature
                    - ips-anomaly
                    - av-virus
                    - av-oversize
                    - av-pattern
                    - av-fragmented
                    - fm-if-change
                    - fm-conf-change
                    - bgp-established
                    - bgp-backward-transition
                    - ha-member-up
                    - ha-member-down
                    - ent-conf-change
                    - av-conserve
                    - av-bypass
                    - av-oversize-passed
                    - av-oversize-blocked
                    - ips-pkg-update
                    - ips-fail-open
                    - faz-disconnect
                    - wc-ap-up
                    - wc-ap-down
                    - fswctl-session-up
                    - fswctl-session-down
                    - load-balance-real-server-down
                    - device-new
                    - per-cpu-high
            ha-direct:
                description:
                    - Enable/disable direct management of HA cluster members.
                choices:
                    - enable
                    - disable
            name:
                description:
                    - SNMP user name.
                required: true
            notify-hosts:
                description:
                    - SNMP managers to send notifications (traps) to.
            notify-hosts6:
                description:
                    - IPv6 SNMP managers to send notifications (traps) to.
            priv-proto:
                description:
                    - Privacy (encryption) protocol.
                choices:
                    - aes
                    - des
                    - aes256
                    - aes256cisco
            priv-pwd:
                description:
                    - Password for privacy (encryption) protocol.
            queries:
                description:
                    - Enable/disable SNMP queries for this user.
                choices:
                    - enable
                    - disable
            query-port:
                description:
                    - SNMPv3 query port (default = 161).
            security-level:
                description:
                    - Security level for message authentication and encryption.
                choices:
                    - no-auth-no-priv
                    - auth-no-priv
                    - auth-priv
            source-ip:
                description:
                    - Source IP for SNMP trap.
            source-ipv6:
                description:
                    - Source IPv6 for SNMP trap.
            status:
                description:
                    - Enable/disable this SNMP user.
                choices:
                    - enable
                    - disable
            trap-lport:
                description:
                    - SNMPv3 local trap port (default = 162).
            trap-rport:
                description:
                    - SNMPv3 trap remote port (default = 162).
            trap-status:
                description:
                    - Enable/disable traps for this SNMP user.
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
  - name: SNMP user configuration.
    fortios_system_snmp_user:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_snmp_user:
        state: "present"
        auth-proto: "md5"
        auth-pwd: "<your_own_value>"
        events: "cpu-high"
        ha-direct: "enable"
        name: "default_name_7"
        notify-hosts: "<your_own_value>"
        notify-hosts6: "<your_own_value>"
        priv-proto: "aes"
        priv-pwd: "<your_own_value>"
        queries: "enable"
        query-port: "13"
        security-level: "no-auth-no-priv"
        source-ip: "84.230.14.43"
        source-ipv6: "<your_own_value>"
        status: "enable"
        trap-lport: "18"
        trap-rport: "19"
        trap-status: "enable"
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


def filter_system_snmp_user_data(json):
    option_list = ['auth-proto', 'auth-pwd', 'events',
                   'ha-direct', 'name', 'notify-hosts',
                   'notify-hosts6', 'priv-proto', 'priv-pwd',
                   'queries', 'query-port', 'security-level',
                   'source-ip', 'source-ipv6', 'status',
                   'trap-lport', 'trap-rport', 'trap-status']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_multilists_attributes(data):
    multilist_attrs = [[u'events']]

    for attr in multilist_attrs:
        try:
            path = "data['" + "']['".join(elem for elem in attr) + "']"
            current_val = eval(path)
            flattened_val = ' '.join(elem for elem in current_val)
            exec(path + '= flattened_val')
        except BaseException:
            pass

    return data


def system_snmp_user(data, fos):
    vdom = data['vdom']
    system_snmp_user_data = data['system_snmp_user']
    system_snmp_user_data = flatten_multilists_attributes(system_snmp_user_data)
    filtered_data = filter_system_snmp_user_data(system_snmp_user_data)

    if system_snmp_user_data['state'] == "present":
        return fos.set('system.snmp',
                       'user',
                       data=filtered_data,
                       vdom=vdom)

    elif system_snmp_user_data['state'] == "absent":
        return fos.delete('system.snmp',
                          'user',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system_snmp(data, fos):
    login(data, fos)

    if data['system_snmp_user']:
        resp = system_snmp_user(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_snmp_user": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "auth-proto": {"required": False, "type": "str",
                               "choices": ["md5", "sha"]},
                "auth-pwd": {"required": False, "type": "str"},
                "events": {"required": False, "type": "list",
                           "choices": ["cpu-high", "mem-low", "log-full",
                                       "intf-ip", "vpn-tun-up", "vpn-tun-down",
                                       "ha-switch", "ha-hb-failure", "ips-signature",
                                       "ips-anomaly", "av-virus", "av-oversize",
                                       "av-pattern", "av-fragmented", "fm-if-change",
                                       "fm-conf-change", "bgp-established", "bgp-backward-transition",
                                       "ha-member-up", "ha-member-down", "ent-conf-change",
                                       "av-conserve", "av-bypass", "av-oversize-passed",
                                       "av-oversize-blocked", "ips-pkg-update", "ips-fail-open",
                                       "faz-disconnect", "wc-ap-up", "wc-ap-down",
                                       "fswctl-session-up", "fswctl-session-down", "load-balance-real-server-down",
                                       "device-new", "per-cpu-high"]},
                "ha-direct": {"required": False, "type": "str",
                              "choices": ["enable", "disable"]},
                "name": {"required": True, "type": "str"},
                "notify-hosts": {"required": False, "type": "str"},
                "notify-hosts6": {"required": False, "type": "str"},
                "priv-proto": {"required": False, "type": "str",
                               "choices": ["aes", "des", "aes256",
                                           "aes256cisco"]},
                "priv-pwd": {"required": False, "type": "str"},
                "queries": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]},
                "query-port": {"required": False, "type": "int"},
                "security-level": {"required": False, "type": "str",
                                   "choices": ["no-auth-no-priv", "auth-no-priv", "auth-priv"]},
                "source-ip": {"required": False, "type": "str"},
                "source-ipv6": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "trap-lport": {"required": False, "type": "int"},
                "trap-rport": {"required": False, "type": "int"},
                "trap-status": {"required": False, "type": "str",
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

    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_system_snmp(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
