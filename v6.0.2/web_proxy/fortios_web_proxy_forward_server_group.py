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
module: fortios_web_proxy_forward_server_group
short_description: Configure a forward server group consisting or multiple forward servers. Supports failover and load balancing in Fortinet's FortiOS and
   FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify web_proxy feature and forward_server_group category.
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
    web_proxy_forward_server_group:
        description:
            - Configure a forward server group consisting or multiple forward servers. Supports failover and load balancing.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            affinity:
                description:
                    - Enable/disable affinity, attaching a source-ip's traffic to the assigned forwarding server until the forward-server-affinity-timeout is
                       reached (under web-proxy global).
                choices:
                    - enable
                    - disable
            group-down-option:
                description:
                    - "Action to take when all of the servers in the forward server group are down: block sessions until at least one server is back up or
                       pass sessions to their destination."
                choices:
                    - block
                    - pass
            ldb-method:
                description:
                    - "Load balance method: weighted or least-session."
                choices:
                    - weighted
                    - least-session
            name:
                description:
                    - Configure a forward server group consisting one or multiple forward servers. Supports failover and load balancing.
                required: true
            server-list:
                description:
                    - Add web forward servers to a list to form a server group. Optionally assign weights to each server.
                suboptions:
                    name:
                        description:
                            - Forward server name. Source web-proxy.forward-server.name.
                        required: true
                    weight:
                        description:
                            - Optionally assign a weight of the forwarding server for weighted load balancing (1 - 100, default = 10)
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure a forward server group consisting or multiple forward servers. Supports failover and load balancing.
    fortios_web_proxy_forward_server_group:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      web_proxy_forward_server_group:
        state: "present"
        affinity: "enable"
        group-down-option: "block"
        ldb-method: "weighted"
        name: "default_name_6"
        server-list:
         -
            name: "default_name_8 (source web-proxy.forward-server.name)"
            weight: "9"
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


def filter_web_proxy_forward_server_group_data(json):
    option_list = ['affinity', 'group-down-option', 'ldb-method',
                   'name', 'server-list']
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


def web_proxy_forward_server_group(data, fos):
    vdom = data['vdom']
    web_proxy_forward_server_group_data = data['web_proxy_forward_server_group']
    flattened_data = flatten_multilists_attributes(web_proxy_forward_server_group_data)
    filtered_data = filter_web_proxy_forward_server_group_data(flattened_data)
    if web_proxy_forward_server_group_data['state'] == "present":
        return fos.set('web-proxy',
                       'forward-server-group',
                       data=filtered_data,
                       vdom=vdom)

    elif web_proxy_forward_server_group_data['state'] == "absent":
        return fos.delete('web-proxy',
                          'forward-server-group',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_web_proxy(data, fos):
    login(data, fos)

    if data['web_proxy_forward_server_group']:
        resp = web_proxy_forward_server_group(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "web_proxy_forward_server_group": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "affinity": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "group-down-option": {"required": False, "type": "str",
                                      "choices": ["block", "pass"]},
                "ldb-method": {"required": False, "type": "str",
                               "choices": ["weighted", "least-session"]},
                "name": {"required": True, "type": "str"},
                "server-list": {"required": False, "type": "list",
                                "options": {
                                    "name": {"required": True, "type": "str"},
                                    "weight": {"required": False, "type": "int"}
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

    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_web_proxy(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
