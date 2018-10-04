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
module: fortios_wanopt_webcache
short_description: Configure global Web cache settings.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wanopt feature and webcache category.
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
    wanopt_webcache:
        description:
            - Configure global Web cache settings.
        default: null
        suboptions:
            always-revalidate:
                description:
                    - Enable/disable revalidation of requested cached objects, which have content on the server, before serving it to the client.
                choices:
                    - enable
                    - disable
            cache-by-default:
                description:
                    - Enable/disable caching content that lacks explicit caching policies from the server.
                choices:
                    - enable
                    - disable
            cache-cookie:
                description:
                    - Enable/disable caching cookies. Since cookies contain information for or about individual users, they not usually cached.
                choices:
                    - enable
                    - disable
            cache-expired:
                description:
                    - Enable/disable caching type-1 objects that are already expired on arrival.
                choices:
                    - enable
                    - disable
            default-ttl:
                description:
                    - Default object expiry time (default = 1440 min (1 day); maximum = 5256000 min (100 years)). This only applies to those objects that do
                       not have an expiry time set by the web server.
            external:
                description:
                    - Enable/disable external Web caching.
                choices:
                    - enable
                    - disable
            fresh-factor:
                description:
                    - Frequency that the server is checked to see if any objects have expired (1 - 100, default = 100). The higher the fresh factor, the less
                       often the checks occur.
            host-validate:
                description:
                    - "Enable/disable validating "Host:" with original server IP."
                choices:
                    - enable
                    - disable
            ignore-conditional:
                description:
                    - Enable/disable controlling the behavior of cache-control HTTP 1.1 header values.
                choices:
                    - enable
                    - disable
            ignore-ie-reload:
                description:
                    - "Enable/disable ignoring the PNC-interpretation of Internet Explorer's Accept: / header."
                choices:
                    - enable
                    - disable
            ignore-ims:
                description:
                    - Enable/disable ignoring the if-modified-since (IMS) header.
                choices:
                    - enable
                    - disable
            ignore-pnc:
                description:
                    - Enable/disable ignoring the pragma no-cache (PNC) header.
                choices:
                    - enable
                    - disable
            max-object-size:
                description:
                    - Maximum cacheable object size in kB (1 - 2147483 kb (2GB). All objects that exceed this are delivered to the client but not stored in
                       the web cache.
            max-ttl:
                description:
                    - Maximum time an object can stay in the web cache without checking to see if it has expired on the server (default = 7200 min (5 days);
                       maximum = 5256000 min (100 years)).
            min-ttl:
                description:
                    - Minimum time an object can stay in the web cache without checking to see if it has expired on the server (default = 5 min; maximum =
                       5256000 (100 years)).
            neg-resp-time:
                description:
                    - Time in minutes to cache negative responses or errors (0 - 4294967295, default = 0  which means negative responses are not cached).
            reval-pnc:
                description:
                    - Enable/disable revalidation of pragma-no-cache (PNC) to address bandwidth concerns.
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
  - name: Configure global Web cache settings.
    fortios_wanopt_webcache:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      wanopt_webcache:
        always-revalidate: "enable"
        cache-by-default: "enable"
        cache-cookie: "enable"
        cache-expired: "enable"
        default-ttl: "7"
        external: "enable"
        fresh-factor: "9"
        host-validate: "enable"
        ignore-conditional: "enable"
        ignore-ie-reload: "enable"
        ignore-ims: "enable"
        ignore-pnc: "enable"
        max-object-size: "15"
        max-ttl: "16"
        min-ttl: "17"
        neg-resp-time: "18"
        reval-pnc: "enable"
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


def filter_wanopt_webcache_data(json):
    option_list = ['always-revalidate', 'cache-by-default', 'cache-cookie',
                   'cache-expired', 'default-ttl', 'external',
                   'fresh-factor', 'host-validate', 'ignore-conditional',
                   'ignore-ie-reload', 'ignore-ims', 'ignore-pnc',
                   'max-object-size', 'max-ttl', 'min-ttl',
                   'neg-resp-time', 'reval-pnc']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def wanopt_webcache(data, fos):
    vdom = data['vdom']
    wanopt_webcache_data = data['wanopt_webcache']
    filtered_data = filter_wanopt_webcache_data(wanopt_webcache_data)
    return fos.set('wanopt',
                   'webcache',
                   data=filtered_data,
                   vdom=vdom)


def fortios_wanopt(data, fos):
    login(data)

    methodlist = ['wanopt_webcache']
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
        "wanopt_webcache": {
            "required": False, "type": "dict",
            "options": {
                "always-revalidate": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "cache-by-default": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "cache-cookie": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "cache-expired": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "default-ttl": {"required": False, "type": "int"},
                "external": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "fresh-factor": {"required": False, "type": "int"},
                "host-validate": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "ignore-conditional": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "ignore-ie-reload": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "ignore-ims": {"required": False, "type": "str",
                               "choices": ["enable", "disable"]},
                "ignore-pnc": {"required": False, "type": "str",
                               "choices": ["enable", "disable"]},
                "max-object-size": {"required": False, "type": "int"},
                "max-ttl": {"required": False, "type": "int"},
                "min-ttl": {"required": False, "type": "int"},
                "neg-resp-time": {"required": False, "type": "int"},
                "reval-pnc": {"required": False, "type": "str",
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
