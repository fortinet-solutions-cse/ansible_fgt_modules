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
module: fortios_wanopt_content_delivery_network_rule
short_description: Configure WAN optimization content delivery network rules in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify wanopt feature and content_delivery_network_rule category.
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
    wanopt_content_delivery_network_rule:
        description:
            - Configure WAN optimization content delivery network rules.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            category:
                description:
                    - Content delivery network rule category.
                choices:
                    - vcache
                    - youtube
            comment:
                description:
                    - Comment about this CDN-rule.
            host-domain-name-suffix:
                description:
                    - Suffix portion of the fully qualified domain name (eg. fortinet.com in "www.fortinet.com").
                suboptions:
                    name:
                        description:
                            - Suffix portion of the fully qualified domain name.
                        required: true
            name:
                description:
                    - Name of table.
                required: true
            request-cache-control:
                description:
                    - Enable/disable HTTP request cache control.
                choices:
                    - enable
                    - disable
            response-cache-control:
                description:
                    - Enable/disable HTTP response cache control.
                choices:
                    - enable
                    - disable
            response-expires:
                description:
                    - Enable/disable HTTP response cache expires.
                choices:
                    - enable
                    - disable
            rules:
                description:
                    - WAN optimization content delivery network rule entries.
                suboptions:
                    content-id:
                        description:
                            - Content ID settings.
                        suboptions:
                            end-direction:
                                description:
                                    - Search direction from end-str match.
                                choices:
                                    - forward
                                    - backward
                            end-skip:
                                description:
                                    - Number of characters in URL to skip after end-str has been matched.
                            end-str:
                                description:
                                    - String from which to end search.
                            range-str:
                                description:
                                    - Name of content ID within the start string and end string.
                            start-direction:
                                description:
                                    - Search direction from start-str match.
                                choices:
                                    - forward
                                    - backward
                            start-skip:
                                description:
                                    - Number of characters in URL to skip after start-str has been matched.
                            start-str:
                                description:
                                    - String from which to start search.
                            target:
                                description:
                                    - Option in HTTP header or URL parameter to match.
                                choices:
                                    - path
                                    - parameter
                                    - referrer
                                    - youtube-map
                                    - youtube-id
                                    - youku-id
                                    - hls-manifest
                                    - dash-manifest
                                    - hls-fragment
                                    - dash-fragment
                    match-entries:
                        description:
                            - List of entries to match.
                        suboptions:
                            id:
                                description:
                                    - Rule ID.
                                required: true
                            pattern:
                                description:
                                    - Pattern string for matching target (Referrer or URL pattern, eg. "a", "a*c", "*a*", "a*c*e", and "*").
                                suboptions:
                                    string:
                                        description:
                                            - Pattern strings.
                                        required: true
                            target:
                                description:
                                    - Option in HTTP header or URL parameter to match.
                                choices:
                                    - path
                                    - parameter
                                    - referrer
                                    - youtube-map
                                    - youtube-id
                                    - youku-id
                    match-mode:
                        description:
                            - Match criteria for collecting content ID.
                        choices:
                            - all
                            - any
                    name:
                        description:
                            - WAN optimization content delivery network rule name.
                        required: true
                    skip-entries:
                        description:
                            - List of entries to skip.
                        suboptions:
                            id:
                                description:
                                    - Rule ID.
                                required: true
                            pattern:
                                description:
                                    - Pattern string for matching target (Referrer or URL pattern, eg. "a", "a*c", "*a*", "a*c*e", and "*").
                                suboptions:
                                    string:
                                        description:
                                            - Pattern strings.
                                        required: true
                            target:
                                description:
                                    - Option in HTTP header or URL parameter to match.
                                choices:
                                    - path
                                    - parameter
                                    - referrer
                                    - youtube-map
                                    - youtube-id
                                    - youku-id
                    skip-rule-mode:
                        description:
                            - Skip mode when evaluating skip-rules.
                        choices:
                            - all
                            - any
            status:
                description:
                    - Enable/disable WAN optimization content delivery network rules.
                choices:
                    - enable
                    - disable
            text-response-vcache:
                description:
                    - Enable/disable caching of text responses.
                choices:
                    - enable
                    - disable
            updateserver:
                description:
                    - Enable/disable update server.
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
  - name: Configure WAN optimization content delivery network rules.
    fortios_wanopt_content_delivery_network_rule:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wanopt_content_delivery_network_rule:
        state: "present"
        category: "vcache"
        comment: "Comment about this CDN-rule."
        host-domain-name-suffix:
         -
            name: "default_name_6"
        name: "default_name_7"
        request-cache-control: "enable"
        response-cache-control: "enable"
        response-expires: "enable"
        rules:
         -
            content-id:
                end-direction: "forward"
                end-skip: "14"
                end-str: "<your_own_value>"
                range-str: "<your_own_value>"
                start-direction: "forward"
                start-skip: "18"
                start-str: "<your_own_value>"
                target: "path"
            match-entries:
             -
                id:  "22"
                pattern:
                 -
                    string: "<your_own_value>"
                target: "path"
            match-mode: "all"
            name: "default_name_27"
            skip-entries:
             -
                id:  "29"
                pattern:
                 -
                    string: "<your_own_value>"
                target: "path"
            skip-rule-mode: "all"
        status: "enable"
        text-response-vcache: "enable"
        updateserver: "enable"
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


def filter_wanopt_content_delivery_network_rule_data(json):
    option_list = ['category', 'comment', 'host-domain-name-suffix',
                   'name', 'request-cache-control', 'response-cache-control',
                   'response-expires', 'rules', 'status',
                   'text-response-vcache', 'updateserver']
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


def wanopt_content_delivery_network_rule(data, fos):
    vdom = data['vdom']
    wanopt_content_delivery_network_rule_data = data['wanopt_content_delivery_network_rule']
    flattened_data = flatten_multilists_attributes(wanopt_content_delivery_network_rule_data)
    filtered_data = filter_wanopt_content_delivery_network_rule_data(flattened_data)
    if wanopt_content_delivery_network_rule_data['state'] == "present":
        return fos.set('wanopt',
                       'content-delivery-network-rule',
                       data=filtered_data,
                       vdom=vdom)

    elif wanopt_content_delivery_network_rule_data['state'] == "absent":
        return fos.delete('wanopt',
                          'content-delivery-network-rule',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wanopt(data, fos):
    login(data)

    methodlist = ['wanopt_content_delivery_network_rule']
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
        "wanopt_content_delivery_network_rule": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "category": {"required": False, "type": "str",
                             "choices": ["vcache", "youtube"]},
                "comment": {"required": False, "type": "str"},
                "host-domain-name-suffix": {"required": False, "type": "list",
                                            "options": {
                                                "name": {"required": True, "type": "str"}
                                            }},
                "name": {"required": True, "type": "str"},
                "request-cache-control": {"required": False, "type": "str",
                                          "choices": ["enable", "disable"]},
                "response-cache-control": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "response-expires": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "rules": {"required": False, "type": "list",
                          "options": {
                              "content-id": {"required": False, "type": "dict",
                                             "options": {
                                                 "end-direction": {"required": False, "type": "str",
                                                                   "choices": ["forward", "backward"]},
                                                 "end-skip": {"required": False, "type": "int"},
                                                 "end-str": {"required": False, "type": "str"},
                                                 "range-str": {"required": False, "type": "str"},
                                                 "start-direction": {"required": False, "type": "str",
                                                                     "choices": ["forward", "backward"]},
                                                 "start-skip": {"required": False, "type": "int"},
                                                 "start-str": {"required": False, "type": "str"},
                                                 "target": {"required": False, "type": "str",
                                                            "choices": ["path", "parameter", "referrer",
                                                                        "youtube-map", "youtube-id", "youku-id",
                                                                        "hls-manifest", "dash-manifest", "hls-fragment",
                                                                        "dash-fragment"]}
                                             }},
                              "match-entries": {"required": False, "type": "list",
                                                "options": {
                                                    "id": {"required": True, "type": "int"},
                                                    "pattern": {"required": False, "type": "list",
                                                                "options": {
                                                                    "string": {"required": True, "type": "str"}
                                                                }},
                                                    "target": {"required": False, "type": "str",
                                                               "choices": ["path", "parameter", "referrer",
                                                                           "youtube-map", "youtube-id", "youku-id"]}
                                                }},
                              "match-mode": {"required": False, "type": "str",
                                             "choices": ["all", "any"]},
                              "name": {"required": True, "type": "str"},
                              "skip-entries": {"required": False, "type": "list",
                                               "options": {
                                                   "id": {"required": True, "type": "int"},
                                                   "pattern": {"required": False, "type": "list",
                                                               "options": {
                                                                   "string": {"required": True, "type": "str"}
                                                               }},
                                                   "target": {"required": False, "type": "str",
                                                              "choices": ["path", "parameter", "referrer",
                                                                          "youtube-map", "youtube-id", "youku-id"]}
                                               }},
                              "skip-rule-mode": {"required": False, "type": "str",
                                                 "choices": ["all", "any"]}
                          }},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "text-response-vcache": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "updateserver": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_wanopt(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
