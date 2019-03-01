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
module: fortios_webfilter_search_engine
short_description: Configure web filter search engines in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify webfilter feature and search_engine category.
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
    webfilter_search_engine:
        description:
            - Configure web filter search engines.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            charset:
                description:
                    - Search engine charset.
                choices:
                    - utf-8
                    - gb2312
            hostname:
                description:
                    - Hostname (regular expression).
            name:
                description:
                    - Search engine name.
                required: true
            query:
                description:
                    - Code used to prefix a query (must end with an equals character).
            safesearch:
                description:
                    - Safe search method. You can disable safe search, add the safe search string to URLs, or insert a safe search header.
                choices:
                    - disable
                    - url
                    - header
            safesearch-str:
                description:
                    - Safe search parameter used in the URL.
            url:
                description:
                    - URL (regular expression).
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure web filter search engines.
    fortios_webfilter_search_engine:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      webfilter_search_engine:
        state: "present"
        charset: "utf-8"
        hostname: "myhostname"
        name: "default_name_5"
        query: "<your_own_value>"
        safesearch: "disable"
        safesearch-str: "<your_own_value>"
        url: "myurl.com"
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


def filter_webfilter_search_engine_data(json):
    option_list = ['charset', 'hostname', 'name',
                   'query', 'safesearch', 'safesearch-str',
                   'url']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def webfilter_search_engine(data, fos):
    vdom = data['vdom']
    webfilter_search_engine_data = data['webfilter_search_engine']
    filtered_data = filter_webfilter_search_engine_data(webfilter_search_engine_data)

    if webfilter_search_engine_data['state'] == "present":
        return fos.set('webfilter',
                       'search-engine',
                       data=filtered_data,
                       vdom=vdom)

    elif webfilter_search_engine_data['state'] == "absent":
        return fos.delete('webfilter',
                          'search-engine',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_webfilter(data, fos):
    login(data, fos)

    if data['webfilter_search_engine']:
        resp = webfilter_search_engine(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "webfilter_search_engine": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "charset": {"required": False, "type": "str",
                            "choices": ["utf-8", "gb2312"]},
                "hostname": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "query": {"required": False, "type": "str"},
                "safesearch": {"required": False, "type": "str",
                               "choices": ["disable", "url", "header"]},
                "safesearch-str": {"required": False, "type": "str"},
                "url": {"required": False, "type": "str"}

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

    is_error, has_changed, result = fortios_webfilter(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
