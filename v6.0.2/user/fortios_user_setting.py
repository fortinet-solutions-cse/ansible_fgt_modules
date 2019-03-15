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
module: fortios_user_setting
short_description: Configure user authentication setting in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify user feature and setting category.
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
    user_setting:
        description:
            - Configure user authentication setting.
        default: null
        suboptions:
            auth-blackout-time:
                description:
                    - Time in seconds an IP address is denied access after failing to authenticate five times within one minute.
            auth-ca-cert:
                description:
                    - HTTPS CA certificate for policy authentication. Source vpn.certificate.local.name.
            auth-cert:
                description:
                    - HTTPS server certificate for policy authentication. Source vpn.certificate.local.name.
            auth-http-basic:
                description:
                    - Enable/disable use of HTTP basic authentication for identity-based firewall policies.
                choices:
                    - enable
                    - disable
            auth-invalid-max:
                description:
                    - Maximum number of failed authentication attempts before the user is blocked.
            auth-lockout-duration:
                description:
                    - Lockout period in seconds after too many login failures.
            auth-lockout-threshold:
                description:
                    - Maximum number of failed login attempts before login lockout is triggered.
            auth-portal-timeout:
                description:
                    - Time in minutes before captive portal user have to re-authenticate (1 - 30 min, default 3 min).
            auth-ports:
                description:
                    - Set up non-standard ports for authentication with HTTP, HTTPS, FTP, and TELNET.
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                    port:
                        description:
                            - Non-standard port for firewall user authentication.
                    type:
                        description:
                            - Service type.
                        choices:
                            - http
                            - https
                            - ftp
                            - telnet
            auth-secure-http:
                description:
                    - Enable/disable redirecting HTTP user authentication to more secure HTTPS.
                choices:
                    - enable
                    - disable
            auth-src-mac:
                description:
                    - Enable/disable source MAC for user identity.
                choices:
                    - enable
                    - disable
            auth-ssl-allow-renegotiation:
                description:
                    - Allow/forbid SSL re-negotiation for HTTPS authentication.
                choices:
                    - enable
                    - disable
            auth-timeout:
                description:
                    - Time in minutes before the firewall user authentication timeout requires the user to re-authenticate.
            auth-timeout-type:
                description:
                    - Control if authenticated users have to login again after a hard timeout, after an idle timeout, or after a session timeout.
                choices:
                    - idle-timeout
                    - hard-timeout
                    - new-session
            auth-type:
                description:
                    - Supported firewall policy authentication protocols/methods.
                choices:
                    - http
                    - https
                    - ftp
                    - telnet
            radius-ses-timeout-act:
                description:
                    - Set the RADIUS session timeout to a hard timeout or to ignore RADIUS server session timeouts.
                choices:
                    - hard-timeout
                    - ignore-timeout
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure user authentication setting.
    fortios_user_setting:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      user_setting:
        auth-blackout-time: "3"
        auth-ca-cert: "<your_own_value> (source vpn.certificate.local.name)"
        auth-cert: "<your_own_value> (source vpn.certificate.local.name)"
        auth-http-basic: "enable"
        auth-invalid-max: "7"
        auth-lockout-duration: "8"
        auth-lockout-threshold: "9"
        auth-portal-timeout: "10"
        auth-ports:
         -
            id:  "12"
            port: "13"
            type: "http"
        auth-secure-http: "enable"
        auth-src-mac: "enable"
        auth-ssl-allow-renegotiation: "enable"
        auth-timeout: "18"
        auth-timeout-type: "idle-timeout"
        auth-type: "http"
        radius-ses-timeout-act: "hard-timeout"
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


def filter_user_setting_data(json):
    option_list = ['auth-blackout-time', 'auth-ca-cert', 'auth-cert',
                   'auth-http-basic', 'auth-invalid-max', 'auth-lockout-duration',
                   'auth-lockout-threshold', 'auth-portal-timeout', 'auth-ports',
                   'auth-secure-http', 'auth-src-mac', 'auth-ssl-allow-renegotiation',
                   'auth-timeout', 'auth-timeout-type', 'auth-type',
                   'radius-ses-timeout-act']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def user_setting(data, fos):
    vdom = data['vdom']
    user_setting_data = data['user_setting']
    filtered_data = filter_user_setting_data(user_setting_data)

    return fos.set('user',
                   'setting',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_user(data, fos):
    login(data, fos)

    if data['user_setting']:
        resp = user_setting(data, fos)

    fos.logout()
    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "user_setting": {
            "required": False, "type": "dict",
            "options": {
                "auth-blackout-time": {"required": False, "type": "int"},
                "auth-ca-cert": {"required": False, "type": "str"},
                "auth-cert": {"required": False, "type": "str"},
                "auth-http-basic": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "auth-invalid-max": {"required": False, "type": "int"},
                "auth-lockout-duration": {"required": False, "type": "int"},
                "auth-lockout-threshold": {"required": False, "type": "int"},
                "auth-portal-timeout": {"required": False, "type": "int"},
                "auth-ports": {"required": False, "type": "list",
                               "options": {
                                   "id": {"required": True, "type": "int"},
                                   "port": {"required": False, "type": "int"},
                                   "type": {"required": False, "type": "str",
                                            "choices": ["http", "https", "ftp",
                                                        "telnet"]}
                               }},
                "auth-secure-http": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "auth-src-mac": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "auth-ssl-allow-renegotiation": {"required": False, "type": "str",
                                                 "choices": ["enable", "disable"]},
                "auth-timeout": {"required": False, "type": "int"},
                "auth-timeout-type": {"required": False, "type": "str",
                                      "choices": ["idle-timeout", "hard-timeout", "new-session"]},
                "auth-type": {"required": False, "type": "str",
                              "choices": ["http", "https", "ftp",
                                          "telnet"]},
                "radius-ses-timeout-act": {"required": False, "type": "str",
                                           "choices": ["hard-timeout", "ignore-timeout"]}

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

    is_error, has_changed, result = fortios_user(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
