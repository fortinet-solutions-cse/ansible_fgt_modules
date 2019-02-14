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
module: fortios_router_route_map
short_description: Configure route maps in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify router feature and route_map category.
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
    router_route_map:
        description:
            - Configure route maps.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            comments:
                description:
                    - Optional comments.
            name:
                description:
                    - Name.
                required: true
            rule:
                description:
                    - Rule.
                suboptions:
                    action:
                        description:
                            - Action.
                        choices:
                            - permit
                            - deny
                    id:
                        description:
                            - Rule ID.
                        required: true
                    match-as-path:
                        description:
                            - Match BGP AS path list. Source router.aspath-list.name.
                    match-community:
                        description:
                            - Match BGP community list. Source router.community-list.name.
                    match-community-exact:
                        description:
                            - Enable/disable exact matching of communities.
                        choices:
                            - enable
                            - disable
                    match-flags:
                        description:
                            - BGP flag value to match (0 - 65535)
                    match-interface:
                        description:
                            - Match interface configuration. Source system.interface.name.
                    match-ip-address:
                        description:
                            - Match IP address permitted by access-list or prefix-list. Source router.access-list.name router.prefix-list.name.
                    match-ip-nexthop:
                        description:
                            - Match next hop IP address passed by access-list or prefix-list. Source router.access-list.name router.prefix-list.name.
                    match-ip6-address:
                        description:
                            - Match IPv6 address permitted by access-list6 or prefix-list6. Source router.access-list6.name router.prefix-list6.name.
                    match-ip6-nexthop:
                        description:
                            - Match next hop IPv6 address passed by access-list6 or prefix-list6. Source router.access-list6.name router.prefix-list6.name.
                    match-metric:
                        description:
                            - Match metric for redistribute routes.
                    match-origin:
                        description:
                            - Match BGP origin code.
                        choices:
                            - none
                            - egp
                            - igp
                            - incomplete
                    match-route-type:
                        description:
                            - Match route type.
                        choices:
                            - 1
                            - 2
                            - none
                    match-tag:
                        description:
                            - Match tag.
                    set-aggregator-as:
                        description:
                            - BGP aggregator AS.
                    set-aggregator-ip:
                        description:
                            - BGP aggregator IP.
                    set-aspath:
                        description:
                            - Prepend BGP AS path attribute.
                        suboptions:
                            as:
                                description:
                                    - "AS number (0 - 42949672). NOTE: Use quotes for repeating numbers, e.g.: "1 1 2"
                    "
                                required: true
                    set-aspath-action:
                        description:
                            - Specify preferred action of set-aspath.
                        choices:
                            - prepend
                            - replace
                    set-atomic-aggregate:
                        description:
                            - Enable/disable BGP atomic aggregate attribute.
                        choices:
                            - enable
                            - disable
                    set-community:
                        description:
                            - BGP community attribute.
                        suboptions:
                            community:
                                description:
                                    - "Attribute: AA|AA:NN|internet|local-AS|no-advertise|no-export."
                                required: true
                    set-community-additive:
                        description:
                            - Enable/disable adding set-community to existing community.
                        choices:
                            - enable
                            - disable
                    set-community-delete:
                        description:
                            - Delete communities matching community list. Source router.community-list.name.
                    set-dampening-max-suppress:
                        description:
                            - Maximum duration to suppress a route (1 - 255 min, 0 = unset).
                    set-dampening-reachability-half-life:
                        description:
                            - Reachability half-life time for the penalty (1 - 45 min, 0 = unset).
                    set-dampening-reuse:
                        description:
                            - Value to start reusing a route (1 - 20000, 0 = unset).
                    set-dampening-suppress:
                        description:
                            - Value to start suppressing a route (1 - 20000, 0 = unset).
                    set-dampening-unreachability-half-life:
                        description:
                            - Unreachability Half-life time for the penalty (1 - 45 min, 0 = unset)
                    set-extcommunity-rt:
                        description:
                            - Route Target extended community.
                        suboptions:
                            community:
                                description:
                                    - "AA:NN."
                                required: true
                    set-extcommunity-soo:
                        description:
                            - Site-of-Origin extended community.
                        suboptions:
                            community:
                                description:
                                    - "AA:NN"
                                required: true
                    set-flags:
                        description:
                            - BGP flags value (0 - 65535)
                    set-ip-nexthop:
                        description:
                            - IP address of next hop.
                    set-ip6-nexthop:
                        description:
                            - IPv6 global address of next hop.
                    set-ip6-nexthop-local:
                        description:
                            - IPv6 local address of next hop.
                    set-local-preference:
                        description:
                            - BGP local preference path attribute.
                    set-metric:
                        description:
                            - Metric value.
                    set-metric-type:
                        description:
                            - Metric type.
                        choices:
                            - 1
                            - 2
                            - none
                    set-origin:
                        description:
                            - BGP origin code.
                        choices:
                            - none
                            - egp
                            - igp
                            - incomplete
                    set-originator-id:
                        description:
                            - BGP originator ID attribute.
                    set-route-tag:
                        description:
                            - Route tag for routing table.
                    set-tag:
                        description:
                            - Tag value.
                    set-weight:
                        description:
                            - BGP weight for routing table.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure route maps.
    fortios_router_route_map:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      router_route_map:
        state: "present"
        comments: "<your_own_value>"
        name: "default_name_4"
        rule:
         -
            action: "permit"
            id:  "7"
            match-as-path: "<your_own_value> (source router.aspath-list.name)"
            match-community: "<your_own_value> (source router.community-list.name)"
            match-community-exact: "enable"
            match-flags: "11"
            match-interface: "<your_own_value> (source system.interface.name)"
            match-ip-address: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
            match-ip-nexthop: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
            match-ip6-address: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
            match-ip6-nexthop: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
            match-metric: "17"
            match-origin: "none"
            match-route-type: "1"
            match-tag: "20"
            set-aggregator-as: "21"
            set-aggregator-ip: "<your_own_value>"
            set-aspath:
             -
                as: "<your_own_value>"
            set-aspath-action: "prepend"
            set-atomic-aggregate: "enable"
            set-community:
             -
                community: "<your_own_value>"
            set-community-additive: "enable"
            set-community-delete: "<your_own_value> (source router.community-list.name)"
            set-dampening-max-suppress: "31"
            set-dampening-reachability-half-life: "32"
            set-dampening-reuse: "33"
            set-dampening-suppress: "34"
            set-dampening-unreachability-half-life: "35"
            set-extcommunity-rt:
             -
                community: "<your_own_value>"
            set-extcommunity-soo:
             -
                community: "<your_own_value>"
            set-flags: "40"
            set-ip-nexthop: "<your_own_value>"
            set-ip6-nexthop: "<your_own_value>"
            set-ip6-nexthop-local: "<your_own_value>"
            set-local-preference: "44"
            set-metric: "45"
            set-metric-type: "1"
            set-origin: "none"
            set-originator-id: "<your_own_value>"
            set-route-tag: "49"
            set-tag: "50"
            set-weight: "51"
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


def filter_router_route_map_data(json):
    option_list = ['comments', 'name', 'rule']
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


def router_route_map(data, fos):
    vdom = data['vdom']
    router_route_map_data = data['router_route_map']
    flattened_data = flatten_multilists_attributes(router_route_map_data)
    filtered_data = filter_router_route_map_data(flattened_data)
    if router_route_map_data['state'] == "present":
        return fos.set('router',
                       'route-map',
                       data=filtered_data,
                       vdom=vdom)

    elif router_route_map_data['state'] == "absent":
        return fos.delete('router',
                          'route-map',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_router(data, fos):
    login(data)

    methodlist = ['router_route_map']
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
        "router_route_map": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "comments": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "rule": {"required": False, "type": "list",
                         "options": {
                             "action": {"required": False, "type": "str",
                                        "choices": ["permit", "deny"]},
                             "id": {"required": True, "type": "int"},
                             "match-as-path": {"required": False, "type": "str"},
                             "match-community": {"required": False, "type": "str"},
                             "match-community-exact": {"required": False, "type": "str",
                                                       "choices": ["enable", "disable"]},
                             "match-flags": {"required": False, "type": "int"},
                             "match-interface": {"required": False, "type": "str"},
                             "match-ip-address": {"required": False, "type": "str"},
                             "match-ip-nexthop": {"required": False, "type": "str"},
                             "match-ip6-address": {"required": False, "type": "str"},
                             "match-ip6-nexthop": {"required": False, "type": "str"},
                             "match-metric": {"required": False, "type": "int"},
                             "match-origin": {"required": False, "type": "str",
                                              "choices": ["none", "egp", "igp",
                                                          "incomplete"]},
                             "match-route-type": {"required": False, "type": "str",
                                                  "choices": ["1", "2", "none"]},
                             "match-tag": {"required": False, "type": "int"},
                             "set-aggregator-as": {"required": False, "type": "int"},
                             "set-aggregator-ip": {"required": False, "type": "str"},
                             "set-aspath": {"required": False, "type": "list",
                                            "options": {
                                                "as": {"required": True, "type": "str"}
                                            }},
                             "set-aspath-action": {"required": False, "type": "str",
                                                   "choices": ["prepend", "replace"]},
                             "set-atomic-aggregate": {"required": False, "type": "str",
                                                      "choices": ["enable", "disable"]},
                             "set-community": {"required": False, "type": "list",
                                               "options": {
                                                   "community": {"required": True, "type": "str"}
                                               }},
                             "set-community-additive": {"required": False, "type": "str",
                                                        "choices": ["enable", "disable"]},
                             "set-community-delete": {"required": False, "type": "str"},
                             "set-dampening-max-suppress": {"required": False, "type": "int"},
                             "set-dampening-reachability-half-life": {"required": False, "type": "int"},
                             "set-dampening-reuse": {"required": False, "type": "int"},
                             "set-dampening-suppress": {"required": False, "type": "int"},
                             "set-dampening-unreachability-half-life": {"required": False, "type": "int"},
                             "set-extcommunity-rt": {"required": False, "type": "list",
                                                     "options": {
                                                         "community": {"required": True, "type": "str"}
                                                     }},
                             "set-extcommunity-soo": {"required": False, "type": "list",
                                                      "options": {
                                                          "community": {"required": True, "type": "str"}
                                                      }},
                             "set-flags": {"required": False, "type": "int"},
                             "set-ip-nexthop": {"required": False, "type": "str"},
                             "set-ip6-nexthop": {"required": False, "type": "str"},
                             "set-ip6-nexthop-local": {"required": False, "type": "str"},
                             "set-local-preference": {"required": False, "type": "int"},
                             "set-metric": {"required": False, "type": "int"},
                             "set-metric-type": {"required": False, "type": "str",
                                                 "choices": ["1", "2", "none"]},
                             "set-origin": {"required": False, "type": "str",
                                            "choices": ["none", "egp", "igp",
                                                        "incomplete"]},
                             "set-originator-id": {"required": False, "type": "str"},
                             "set-route-tag": {"required": False, "type": "int"},
                             "set-tag": {"required": False, "type": "int"},
                             "set-weight": {"required": False, "type": "int"}
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

    is_error, has_changed, result = fortios_router(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
