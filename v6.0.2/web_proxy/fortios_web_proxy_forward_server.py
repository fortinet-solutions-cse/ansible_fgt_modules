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
module: fortios_web_proxy_forward_server
short_description: Configure forward-server addresses in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify web_proxy feature and forward_server category.
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
    web_proxy_forward_server:
        description:
            - Configure forward-server addresses.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            addr-type:
                description:
                    - "Address type of the forwarding proxy server: IP or FQDN."
                choices:
                    - ip
                    - fqdn
            comment:
                description:
                    - Comment.
            fqdn:
                description:
                    - Forward server Fully Qualified Domain Name (FQDN).
            healthcheck:
                description:
                    - Enable/disable forward server health checking. Attempts to connect through the remote forwarding server to a destination to verify that
                       the forwarding server is operating normally.
                choices:
                    - disable
                    - enable
            ip:
                description:
                    - Forward proxy server IP address.
            monitor:
                description:
                    - "URL for forward server health check monitoring (default = http://www.google.com)."
            name:
                description:
                    - Server name.
                required: true
            port:
                description:
                    - Port number that the forwarding server expects to receive HTTP sessions on (1 - 65535, default = 3128).
            server-down-option:
                description:
                    - "Action to take when the forward server is found to be down: block sessions until the server is back up or pass sessions to their
                       destination."
                choices:
                    - block
                    - pass
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure forward-server addresses.
    fortios_web_proxy_forward_server:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      web_proxy_forward_server:
        state: "present"
        addr-type: "ip"
        comment: "Comment."
        fqdn: "<your_own_value>"
        healthcheck: "disable"
        ip: "<your_own_value>"
        monitor: "<your_own_value>"
        name: "default_name_9"
        port: "10"
        server-down-option: "block"
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


def filter_web_proxy_forward_server_data(json):
    option_list = ['addr-type', 'comment', 'fqdn',
                   'healthcheck', 'ip', 'monitor',
                   'name', 'port', 'server-down-option']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def web_proxy_forward_server(data, fos):
    vdom = data['vdom']
    web_proxy_forward_server_data = data['web_proxy_forward_server']
    filtered_data = filter_web_proxy_forward_server_data(web_proxy_forward_server_data)

    if web_proxy_forward_server_data['state'] == "present":
        return fos.set('web-proxy',
                       'forward-server',
                       data=filtered_data,
                       vdom=vdom)

    elif web_proxy_forward_server_data['state'] == "absent":
        return fos.delete('web-proxy',
                          'forward-server',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_web_proxy(data, fos):
    login(data, fos)

    if data['web_proxy_forward_server']:
        resp = web_proxy_forward_server(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "web_proxy_forward_server": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "addr-type": {"required": False, "type": "str",
                              "choices": ["ip", "fqdn"]},
                "comment": {"required": False, "type": "str"},
                "fqdn": {"required": False, "type": "str"},
                "healthcheck": {"required": False, "type": "str",
                                "choices": ["disable", "enable"]},
                "ip": {"required": False, "type": "str"},
                "monitor": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "port": {"required": False, "type": "int"},
                "server-down-option": {"required": False, "type": "str",
                                       "choices": ["block", "pass"]}

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

    is_error, has_changed, result = fortios_web_proxy(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
