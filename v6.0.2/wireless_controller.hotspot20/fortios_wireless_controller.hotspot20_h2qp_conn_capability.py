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
module: fortios_wireless_controller.hotspot20_h2qp_conn_capability
short_description: Configure connection capability.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wireless_controller.hotspot20 feature and h2qp_conn_capability category.
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
    wireless_controller.hotspot20_h2qp_conn_capability:
        description:
            - Configure connection capability.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            esp-port:
                description:
                    - Set ESP port service (used by IPsec VPNs) status.
                choices:
                    - closed
                    - open
                    - unknown
            ftp-port:
                description:
                    - Set FTP port service status.
                choices:
                    - closed
                    - open
                    - unknown
            http-port:
                description:
                    - Set HTTP port service status.
                choices:
                    - closed
                    - open
                    - unknown
            icmp-port:
                description:
                    - Set ICMP port service status.
                choices:
                    - closed
                    - open
                    - unknown
            ikev2-port:
                description:
                    - Set IKEv2 port service for IPsec VPN status.
                choices:
                    - closed
                    - open
                    - unknown
            ikev2-xx-port:
                description:
                    - Set UDP port 4500 (which may be used by IKEv2 for IPsec VPN) service status.
                choices:
                    - closed
                    - open
                    - unknown
            name:
                description:
                    - Connection capability name.
                required: true
            pptp-vpn-port:
                description:
                    - Set Point to Point Tunneling Protocol (PPTP) VPN port service status.
                choices:
                    - closed
                    - open
                    - unknown
            ssh-port:
                description:
                    - Set SSH port service status.
                choices:
                    - closed
                    - open
                    - unknown
            tls-port:
                description:
                    - Set TLS VPN (HTTPS) port service status.
                choices:
                    - closed
                    - open
                    - unknown
            voip-tcp-port:
                description:
                    - Set VoIP TCP port service status.
                choices:
                    - closed
                    - open
                    - unknown
            voip-udp-port:
                description:
                    - Set VoIP UDP port service status.
                choices:
                    - closed
                    - open
                    - unknown
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure connection capability.
    fortios_wireless_controller.hotspot20_h2qp_conn_capability:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      wireless_controller.hotspot20_h2qp_conn_capability:
        state: "present"
        esp-port: "closed"
        ftp-port: "closed"
        http-port: "closed"
        icmp-port: "closed"
        ikev2-port: "closed"
        ikev2-xx-port: "closed"
        name: "default_name_9"
        pptp-vpn-port: "closed"
        ssh-port: "closed"
        tls-port: "closed"
        voip-tcp-port: "closed"
        voip-udp-port: "closed"
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


def filter_wireless_controller.hotspot20_h2qp_conn_capability_data(json):
    option_list = ['esp-port', 'ftp-port', 'http-port',
                   'icmp-port', 'ikev2-port', 'ikev2-xx-port',
                   'name', 'pptp-vpn-port', 'ssh-port',
                   'tls-port', 'voip-tcp-port', 'voip-udp-port']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def wireless_controller.hotspot20_h2qp_conn_capability(data, fos):
    vdom = data['vdom']
    wireless_controller.hotspot20_h2qp_conn_capability_data = data[
        'wireless_controller.hotspot20_h2qp_conn_capability']
    filtered_data = filter_wireless_controller.hotspot20_h2qp_conn_capability_data(
        wireless_controller.hotspot20_h2qp_conn_capability_data)
    if wireless_controller.hotspot20_h2qp_conn_capability_data['state'] == "present":
        return fos.set('wireless-controller.hotspot20',
                       'h2qp-conn-capability',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller.hotspot20_h2qp_conn_capability_data['state'] == "absent":
        return fos.delete('wireless-controller.hotspot20',
                          'h2qp-conn-capability',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller.hotspot20(data, fos):
    login(data)

    methodlist = ['wireless_controller.hotspot20_h2qp_conn_capability']
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
        "wireless_controller.hotspot20_h2qp_conn_capability": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "esp-port": {"required": False, "type": "str",
                             "choices": ["closed", "open", "unknown"]},
                "ftp-port": {"required": False, "type": "str",
                             "choices": ["closed", "open", "unknown"]},
                "http-port": {"required": False, "type": "str",
                              "choices": ["closed", "open", "unknown"]},
                "icmp-port": {"required": False, "type": "str",
                              "choices": ["closed", "open", "unknown"]},
                "ikev2-port": {"required": False, "type": "str",
                               "choices": ["closed", "open", "unknown"]},
                "ikev2-xx-port": {"required": False, "type": "str",
                                  "choices": ["closed", "open", "unknown"]},
                "name": {"required": True, "type": "str"},
                "pptp-vpn-port": {"required": False, "type": "str",
                                  "choices": ["closed", "open", "unknown"]},
                "ssh-port": {"required": False, "type": "str",
                             "choices": ["closed", "open", "unknown"]},
                "tls-port": {"required": False, "type": "str",
                             "choices": ["closed", "open", "unknown"]},
                "voip-tcp-port": {"required": False, "type": "str",
                                  "choices": ["closed", "open", "unknown"]},
                "voip-udp-port": {"required": False, "type": "str",
                                  "choices": ["closed", "open", "unknown"]}

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

    is_error, has_changed, result = fortios_wireless_controller.hotspot20(
        module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
