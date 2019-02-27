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
module: fortios_alertemail_setting
short_description: Configure alert email settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify alertemail feature and setting category.
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
    alertemail_setting:
        description:
            - Configure alert email settings.
        default: null
        suboptions:
            admin-login-logs:
                description:
                    - Enable/disable administrator login/logout logs in alert email.
                choices:
                    - enable
                    - disable
            alert-interval:
                description:
                    - Alert alert interval in minutes.
            amc-interface-bypass-mode:
                description:
                    - Enable/disable Fortinet Advanced Mezzanine Card (AMC) interface bypass mode logs in alert email.
                choices:
                    - enable
                    - disable
            antivirus-logs:
                description:
                    - Enable/disable antivirus logs in alert email.
                choices:
                    - enable
                    - disable
            configuration-changes-logs:
                description:
                    - Enable/disable configuration change logs in alert email.
                choices:
                    - enable
                    - disable
            critical-interval:
                description:
                    - Critical alert interval in minutes.
            debug-interval:
                description:
                    - Debug alert interval in minutes.
            email-interval:
                description:
                    - Interval between sending alert emails (1 - 99999 min, default = 5).
            emergency-interval:
                description:
                    - Emergency alert interval in minutes.
            error-interval:
                description:
                    - Error alert interval in minutes.
            FDS-license-expiring-days:
                description:
                    - Number of days to send alert email prior to FortiGuard license expiration (1 - 100 days, default = 100).
            FDS-license-expiring-warning:
                description:
                    - Enable/disable FortiGuard license expiration warnings in alert email.
                choices:
                    - enable
                    - disable
            FDS-update-logs:
                description:
                    - Enable/disable FortiGuard update logs in alert email.
                choices:
                    - enable
                    - disable
            filter-mode:
                description:
                    - How to filter log messages that are sent to alert emails.
                choices:
                    - category
                    - threshold
            FIPS-CC-errors:
                description:
                    - Enable/disable FIPS and Common Criteria error logs in alert email.
                choices:
                    - enable
                    - disable
            firewall-authentication-failure-logs:
                description:
                    - Enable/disable firewall authentication failure logs in alert email.
                choices:
                    - enable
                    - disable
            fortiguard-log-quota-warning:
                description:
                    - Enable/disable FortiCloud log quota warnings in alert email.
                choices:
                    - enable
                    - disable
            FSSO-disconnect-logs:
                description:
                    - Enable/disable logging of FSSO collector agent disconnect.
                choices:
                    - enable
                    - disable
            HA-logs:
                description:
                    - Enable/disable HA logs in alert email.
                choices:
                    - enable
                    - disable
            information-interval:
                description:
                    - Information alert interval in minutes.
            IPS-logs:
                description:
                    - Enable/disable IPS logs in alert email.
                choices:
                    - enable
                    - disable
            IPsec-errors-logs:
                description:
                    - Enable/disable IPsec error logs in alert email.
                choices:
                    - enable
                    - disable
            local-disk-usage:
                description:
                    - Disk usage percentage at which to send alert email (1 - 99 percent, default = 75).
            log-disk-usage-warning:
                description:
                    - Enable/disable disk usage warnings in alert email.
                choices:
                    - enable
                    - disable
            mailto1:
                description:
                    - Email address to send alert email to (usually a system administrator) (max. 64 characters).
            mailto2:
                description:
                    - Optional second email address to send alert email to (max. 64 characters).
            mailto3:
                description:
                    - Optional third email address to send alert email to (max. 64 characters).
            notification-interval:
                description:
                    - Notification alert interval in minutes.
            PPP-errors-logs:
                description:
                    - Enable/disable PPP error logs in alert email.
                choices:
                    - enable
                    - disable
            severity:
                description:
                    - Lowest severity level to log.
                choices:
                    - emergency
                    - alert
                    - critical
                    - error
                    - warning
                    - notification
                    - information
                    - debug
            ssh-logs:
                description:
                    - Enable/disable SSH logs in alert email.
                choices:
                    - enable
                    - disable
            sslvpn-authentication-errors-logs:
                description:
                    - Enable/disable SSL-VPN authentication error logs in alert email.
                choices:
                    - enable
                    - disable
            username:
                description:
                    - "Name that appears in the From: field of alert emails (max. 36 characters)."
            violation-traffic-logs:
                description:
                    - Enable/disable violation traffic logs in alert email.
                choices:
                    - enable
                    - disable
            warning-interval:
                description:
                    - Warning alert interval in minutes.
            webfilter-logs:
                description:
                    - Enable/disable web filter logs in alert email.
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
  - name: Configure alert email settings.
    fortios_alertemail_setting:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      alertemail_setting:
        admin-login-logs: "enable"
        alert-interval: "4"
        amc-interface-bypass-mode: "enable"
        antivirus-logs: "enable"
        configuration-changes-logs: "enable"
        critical-interval: "8"
        debug-interval: "9"
        email-interval: "10"
        emergency-interval: "11"
        error-interval: "12"
        FDS-license-expiring-days: "13"
        FDS-license-expiring-warning: "enable"
        FDS-update-logs: "enable"
        filter-mode: "category"
        FIPS-CC-errors: "enable"
        firewall-authentication-failure-logs: "enable"
        fortiguard-log-quota-warning: "enable"
        FSSO-disconnect-logs: "enable"
        HA-logs: "enable"
        information-interval: "22"
        IPS-logs: "enable"
        IPsec-errors-logs: "enable"
        local-disk-usage: "25"
        log-disk-usage-warning: "enable"
        mailto1: "<your_own_value>"
        mailto2: "<your_own_value>"
        mailto3: "<your_own_value>"
        notification-interval: "30"
        PPP-errors-logs: "enable"
        severity: "emergency"
        ssh-logs: "enable"
        sslvpn-authentication-errors-logs: "enable"
        username: "<your_own_value>"
        violation-traffic-logs: "enable"
        warning-interval: "37"
        webfilter-logs: "enable"
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


def filter_alertemail_setting_data(json):
    option_list = ['admin-login-logs', 'alert-interval', 'amc-interface-bypass-mode',
                   'antivirus-logs', 'configuration-changes-logs', 'critical-interval',
                   'debug-interval', 'email-interval', 'emergency-interval',
                   'error-interval', 'FDS-license-expiring-days', 'FDS-license-expiring-warning',
                   'FDS-update-logs', 'filter-mode', 'FIPS-CC-errors',
                   'firewall-authentication-failure-logs', 'fortiguard-log-quota-warning', 'FSSO-disconnect-logs',
                   'HA-logs', 'information-interval', 'IPS-logs',
                   'IPsec-errors-logs', 'local-disk-usage', 'log-disk-usage-warning',
                   'mailto1', 'mailto2', 'mailto3',
                   'notification-interval', 'PPP-errors-logs', 'severity',
                   'ssh-logs', 'sslvpn-authentication-errors-logs', 'username',
                   'violation-traffic-logs', 'warning-interval', 'webfilter-logs']
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


def alertemail_setting(data, fos):
    vdom = data['vdom']
    alertemail_setting_data = data['alertemail_setting']
    flattened_data = flatten_multilists_attributes(alertemail_setting_data)
    filtered_data = filter_alertemail_setting_data(flattened_data)
    return fos.set('alertemail',
                   'setting',
                   data=filtered_data,
                   vdom=vdom)


def fortios_alertemail(data, fos):
    login(data, fos)

    if data['alertemail_setting']:
        resp = alertemail_setting(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "alertemail_setting": {
            "required": False, "type": "dict",
            "options": {
                "admin-login-logs": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "alert-interval": {"required": False, "type": "int"},
                "amc-interface-bypass-mode": {"required": False, "type": "str",
                                              "choices": ["enable", "disable"]},
                "antivirus-logs": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "configuration-changes-logs": {"required": False, "type": "str",
                                               "choices": ["enable", "disable"]},
                "critical-interval": {"required": False, "type": "int"},
                "debug-interval": {"required": False, "type": "int"},
                "email-interval": {"required": False, "type": "int"},
                "emergency-interval": {"required": False, "type": "int"},
                "error-interval": {"required": False, "type": "int"},
                "FDS-license-expiring-days": {"required": False, "type": "int"},
                "FDS-license-expiring-warning": {"required": False, "type": "str",
                                                 "choices": ["enable", "disable"]},
                "FDS-update-logs": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "filter-mode": {"required": False, "type": "str",
                                "choices": ["category", "threshold"]},
                "FIPS-CC-errors": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "firewall-authentication-failure-logs": {"required": False, "type": "str",
                                                         "choices": ["enable", "disable"]},
                "fortiguard-log-quota-warning": {"required": False, "type": "str",
                                                 "choices": ["enable", "disable"]},
                "FSSO-disconnect-logs": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "HA-logs": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]},
                "information-interval": {"required": False, "type": "int"},
                "IPS-logs": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "IPsec-errors-logs": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "local-disk-usage": {"required": False, "type": "int"},
                "log-disk-usage-warning": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "mailto1": {"required": False, "type": "str"},
                "mailto2": {"required": False, "type": "str"},
                "mailto3": {"required": False, "type": "str"},
                "notification-interval": {"required": False, "type": "int"},
                "PPP-errors-logs": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "severity": {"required": False, "type": "str",
                             "choices": ["emergency", "alert", "critical",
                                         "error", "warning", "notification",
                                         "information", "debug"]},
                "ssh-logs": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "sslvpn-authentication-errors-logs": {"required": False, "type": "str",
                                                      "choices": ["enable", "disable"]},
                "username": {"required": False, "type": "str"},
                "violation-traffic-logs": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "warning-interval": {"required": False, "type": "int"},
                "webfilter-logs": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_alertemail(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
