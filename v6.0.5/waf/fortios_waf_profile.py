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
module: fortios_waf_profile
short_description: Web application firewall configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify waf feature and profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.5
version_added: "2.9"
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
            - FortiOS or FortiGate IP address.
        type: str
        required: true
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        choices:
            - present
            - absent
    waf_profile:
        description:
            - Web application firewall configuration.
        default: null
        type: dict
        suboptions:
            address_list:
                description:
                    - Black address list and white address list.
                suboptions:
                    blocked_address:
                        description:
                            - Blocked address.
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                    blocked_log:
                        description:
                            - Enable/disable logging on blocked addresses.
                        choices:
                            - enable
                            - disable
                    severity:
                        description:
                            - Severity.
                        choices:
                            - high
                            - medium
                            - low
                    status:
                        description:
                            - Status.
                        choices:
                            - enable
                            - disable
                    trusted_address:
                        description:
                            - Trusted address.
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
            comment:
                description:
                    - Comment.
            constraint:
                description:
                    - WAF HTTP protocol restrictions.
                suboptions:
                    content_length:
                        description:
                            - HTTP content length in request.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            length:
                                description:
                                    - Length of HTTP content in bytes (0 to 2147483647).
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    exception:
                        description:
                            - HTTP constraint exception.
                        suboptions:
                            address:
                                description:
                                    - Host address. Source firewall.address.name firewall.addrgrp.name.
                            content_length:
                                description:
                                    - HTTP content length in request.
                                choices:
                                    - enable
                                    - disable
                            header_length:
                                description:
                                    - HTTP header length in request.
                                choices:
                                    - enable
                                    - disable
                            hostname:
                                description:
                                    - Enable/disable hostname check.
                                choices:
                                    - enable
                                    - disable
                            id:
                                description:
                                    - Exception ID.
                                required: true
                            line_length:
                                description:
                                    - HTTP line length in request.
                                choices:
                                    - enable
                                    - disable
                            malformed:
                                description:
                                    - Enable/disable malformed HTTP request check.
                                choices:
                                    - enable
                                    - disable
                            max_cookie:
                                description:
                                    - Maximum number of cookies in HTTP request.
                                choices:
                                    - enable
                                    - disable
                            max_header_line:
                                description:
                                    - Maximum number of HTTP header line.
                                choices:
                                    - enable
                                    - disable
                            max_range_segment:
                                description:
                                    - Maximum number of range segments in HTTP range line.
                                choices:
                                    - enable
                                    - disable
                            max_url_param:
                                description:
                                    - Maximum number of parameters in URL.
                                choices:
                                    - enable
                                    - disable
                            method:
                                description:
                                    - Enable/disable HTTP method check.
                                choices:
                                    - enable
                                    - disable
                            param_length:
                                description:
                                    - Maximum length of parameter in URL, HTTP POST request or HTTP body.
                                choices:
                                    - enable
                                    - disable
                            pattern:
                                description:
                                    - URL pattern.
                            regex:
                                description:
                                    - Enable/disable regular expression based pattern match.
                                choices:
                                    - enable
                                    - disable
                            url_param_length:
                                description:
                                    - Maximum length of parameter in URL.
                                choices:
                                    - enable
                                    - disable
                            version:
                                description:
                                    - Enable/disable HTTP version check.
                                choices:
                                    - enable
                                    - disable
                    header_length:
                        description:
                            - HTTP header length in request.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            length:
                                description:
                                    - Length of HTTP header in bytes (0 to 2147483647).
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    hostname:
                        description:
                            - Enable/disable hostname check.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    line_length:
                        description:
                            - HTTP line length in request.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            length:
                                description:
                                    - Length of HTTP line in bytes (0 to 2147483647).
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    malformed:
                        description:
                            - Enable/disable malformed HTTP request check.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    max_cookie:
                        description:
                            - Maximum number of cookies in HTTP request.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            max_cookie:
                                description:
                                    - Maximum number of cookies in HTTP request (0 to 2147483647).
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    max_header_line:
                        description:
                            - Maximum number of HTTP header line.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            max_header_line:
                                description:
                                    - Maximum number HTTP header lines (0 to 2147483647).
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    max_range_segment:
                        description:
                            - Maximum number of range segments in HTTP range line.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            max_range_segment:
                                description:
                                    - Maximum number of range segments in HTTP range line (0 to 2147483647).
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    max_url_param:
                        description:
                            - Maximum number of parameters in URL.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            max_url_param:
                                description:
                                    - Maximum number of parameters in URL (0 to 2147483647).
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    method:
                        description:
                            - Enable/disable HTTP method check.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    param_length:
                        description:
                            - Maximum length of parameter in URL, HTTP POST request or HTTP body.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            length:
                                description:
                                    - Maximum length of parameter in URL, HTTP POST request or HTTP body in bytes (0 to 2147483647).
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    url_param_length:
                        description:
                            - Maximum length of parameter in URL.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            length:
                                description:
                                    - Maximum length of URL parameter in bytes (0 to 2147483647).
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
                    version:
                        description:
                            - Enable/disable HTTP version check.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Enable/disable the constraint.
                                choices:
                                    - enable
                                    - disable
            extended_log:
                description:
                    - Enable/disable extended logging.
                choices:
                    - enable
                    - disable
            external:
                description:
                    - Disable/Enable external HTTP Inspection.
                choices:
                    - disable
                    - enable
            method:
                description:
                    - Method restriction.
                suboptions:
                    default_allowed_methods:
                        description:
                            - Methods.
                        choices:
                            - get
                            - post
                            - put
                            - head
                            - connect
                            - trace
                            - options
                            - delete
                            - others
                    log:
                        description:
                            - Enable/disable logging.
                        choices:
                            - enable
                            - disable
                    method_policy:
                        description:
                            - HTTP method policy.
                        suboptions:
                            address:
                                description:
                                    - Host address. Source firewall.address.name firewall.addrgrp.name.
                            allowed_methods:
                                description:
                                    - Allowed Methods.
                                choices:
                                    - get
                                    - post
                                    - put
                                    - head
                                    - connect
                                    - trace
                                    - options
                                    - delete
                                    - others
                            id:
                                description:
                                    - HTTP method policy ID.
                                required: true
                            pattern:
                                description:
                                    - URL pattern.
                            regex:
                                description:
                                    - Enable/disable regular expression based pattern match.
                                choices:
                                    - enable
                                    - disable
                    severity:
                        description:
                            - Severity.
                        choices:
                            - high
                            - medium
                            - low
                    status:
                        description:
                            - Status.
                        choices:
                            - enable
                            - disable
            name:
                description:
                    - WAF Profile name.
                required: true
            signature:
                description:
                    - WAF signatures.
                suboptions:
                    credit_card_detection_threshold:
                        description:
                            - The minimum number of Credit cards to detect violation.
                    custom_signature:
                        description:
                            - Custom signature.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                                    - erase
                            case_sensitivity:
                                description:
                                    - Case sensitivity in pattern.
                                choices:
                                    - disable
                                    - enable
                            direction:
                                description:
                                    - Traffic direction.
                                choices:
                                    - request
                                    - response
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            name:
                                description:
                                    - Signature name.
                                required: true
                            pattern:
                                description:
                                    - Match pattern.
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Status.
                                choices:
                                    - enable
                                    - disable
                            target:
                                description:
                                    - Match HTTP target.
                                choices:
                                    - arg
                                    - arg-name
                                    - req-body
                                    - req-cookie
                                    - req-cookie-name
                                    - req-filename
                                    - req-header
                                    - req-header-name
                                    - req-raw-uri
                                    - req-uri
                                    - resp-body
                                    - resp-hdr
                                    - resp-status
                    disabled_signature:
                        description:
                            - Disabled signatures
                        suboptions:
                            id:
                                description:
                                    - Signature ID. Source waf.signature.id.
                                required: true
                    disabled_sub_class:
                        description:
                            - Disabled signature subclasses.
                        suboptions:
                            id:
                                description:
                                    - Signature subclass ID. Source waf.sub-class.id.
                                required: true
                    main_class:
                        description:
                            - Main signature class.
                        suboptions:
                            action:
                                description:
                                    - Action.
                                choices:
                                    - allow
                                    - block
                                    - erase
                            id:
                                description:
                                    - Main signature class ID. Source waf.main-class.id.
                                required: true
                            log:
                                description:
                                    - Enable/disable logging.
                                choices:
                                    - enable
                                    - disable
                            severity:
                                description:
                                    - Severity.
                                choices:
                                    - high
                                    - medium
                                    - low
                            status:
                                description:
                                    - Status.
                                choices:
                                    - enable
                                    - disable
            url_access:
                description:
                    - URL access list
                suboptions:
                    access_pattern:
                        description:
                            - URL access pattern.
                        suboptions:
                            id:
                                description:
                                    - URL access pattern ID.
                                required: true
                            negate:
                                description:
                                    - Enable/disable match negation.
                                choices:
                                    - enable
                                    - disable
                            pattern:
                                description:
                                    - URL pattern.
                            regex:
                                description:
                                    - Enable/disable regular expression based pattern match.
                                choices:
                                    - enable
                                    - disable
                            srcaddr:
                                description:
                                    - Source address. Source firewall.address.name firewall.addrgrp.name.
                    action:
                        description:
                            - Action.
                        choices:
                            - bypass
                            - permit
                            - block
                    address:
                        description:
                            - Host address. Source firewall.address.name firewall.addrgrp.name.
                    id:
                        description:
                            - URL access ID.
                        required: true
                    log:
                        description:
                            - Enable/disable logging.
                        choices:
                            - enable
                            - disable
                    severity:
                        description:
                            - Severity.
                        choices:
                            - high
                            - medium
                            - low
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Web application firewall configuration.
    fortios_waf_profile:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      waf_profile:
        address_list:
            blocked_address:
             -
                name: "default_name_5 (source firewall.address.name firewall.addrgrp.name)"
            blocked_log: "enable"
            severity: "high"
            status: "enable"
            trusted_address:
             -
                name: "default_name_10 (source firewall.address.name firewall.addrgrp.name)"
        comment: "Comment."
        constraint:
            content_length:
                action: "allow"
                length: "15"
                log: "enable"
                severity: "high"
                status: "enable"
            exception:
             -
                address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                content_length: "enable"
                header_length: "enable"
                hostname: "enable"
                id:  "24"
                line_length: "enable"
                malformed: "enable"
                max_cookie: "enable"
                max_header_line: "enable"
                max_range_segment: "enable"
                max_url_param: "enable"
                method: "enable"
                param_length: "enable"
                pattern: "<your_own_value>"
                regex: "enable"
                url_param_length: "enable"
                version: "enable"
            header_length:
                action: "allow"
                length: "39"
                log: "enable"
                severity: "high"
                status: "enable"
            hostname:
                action: "allow"
                log: "enable"
                severity: "high"
                status: "enable"
            line_length:
                action: "allow"
                length: "50"
                log: "enable"
                severity: "high"
                status: "enable"
            malformed:
                action: "allow"
                log: "enable"
                severity: "high"
                status: "enable"
            max_cookie:
                action: "allow"
                log: "enable"
                max_cookie: "62"
                severity: "high"
                status: "enable"
            max_header_line:
                action: "allow"
                log: "enable"
                max_header_line: "68"
                severity: "high"
                status: "enable"
            max_range_segment:
                action: "allow"
                log: "enable"
                max_range_segment: "74"
                severity: "high"
                status: "enable"
            max_url_param:
                action: "allow"
                log: "enable"
                max_url_param: "80"
                severity: "high"
                status: "enable"
            method:
                action: "allow"
                log: "enable"
                severity: "high"
                status: "enable"
            param_length:
                action: "allow"
                length: "90"
                log: "enable"
                severity: "high"
                status: "enable"
            url_param_length:
                action: "allow"
                length: "96"
                log: "enable"
                severity: "high"
                status: "enable"
            version:
                action: "allow"
                log: "enable"
                severity: "high"
                status: "enable"
        extended_log: "enable"
        external: "disable"
        method:
            default_allowed_methods: "get"
            log: "enable"
            method_policy:
             -
                address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                allowed_methods: "get"
                id:  "113"
                pattern: "<your_own_value>"
                regex: "enable"
            severity: "high"
            status: "enable"
        name: "default_name_118"
        signature:
            credit_card_detection_threshold: "120"
            custom_signature:
             -
                action: "allow"
                case_sensitivity: "disable"
                direction: "request"
                log: "enable"
                name: "default_name_126"
                pattern: "<your_own_value>"
                severity: "high"
                status: "enable"
                target: "arg"
            disabled_signature:
             -
                id:  "132 (source waf.signature.id)"
            disabled_sub_class:
             -
                id:  "134 (source waf.sub-class.id)"
            main_class:
             -
                action: "allow"
                id:  "137 (source waf.main-class.id)"
                log: "enable"
                severity: "high"
                status: "enable"
        url_access:
         -
            access_pattern:
             -
                id:  "143"
                negate: "enable"
                pattern: "<your_own_value>"
                regex: "enable"
                srcaddr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
            action: "bypass"
            address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
            id:  "150"
            log: "enable"
            severity: "high"
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
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortios.fortios import FortiOSHandler
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG


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


def filter_waf_profile_data(json):
    option_list = ['address_list', 'comment', 'constraint',
                   'extended_log', 'external', 'method',
                   'name', 'signature', 'url_access']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for elem in data:
            elem = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def waf_profile(data, fos):
    vdom = data['vdom']
    state = data['state']
    waf_profile_data = data['waf_profile']
    filtered_data = underscore_to_hyphen(filter_waf_profile_data(waf_profile_data))

    if state == "present":
        return fos.set('waf',
                       'profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('waf',
                          'profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_waf(data, fos):

    if data['waf_profile']:
        resp = waf_profile(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "waf_profile": {
            "required": False, "type": "dict",
            "options": {
                "address_list": {"required": False, "type": "dict",
                                 "options": {
                                     "blocked_address": {"required": False, "type": "list",
                                                         "options": {
                                                             "name": {"required": True, "type": "str"}
                                                         }},
                                     "blocked_log": {"required": False, "type": "str",
                                                     "choices": ["enable", "disable"]},
                                     "severity": {"required": False, "type": "str",
                                                  "choices": ["high", "medium", "low"]},
                                     "status": {"required": False, "type": "str",
                                                "choices": ["enable", "disable"]},
                                     "trusted_address": {"required": False, "type": "list",
                                                         "options": {
                                                             "name": {"required": True, "type": "str"}
                                                         }}
                                 }},
                "comment": {"required": False, "type": "str"},
                "constraint": {"required": False, "type": "dict",
                               "options": {
                                   "content_length": {"required": False, "type": "dict",
                                                      "options": {
                                                          "action": {"required": False, "type": "str",
                                                                     "choices": ["allow", "block"]},
                                                          "length": {"required": False, "type": "int"},
                                                          "log": {"required": False, "type": "str",
                                                                  "choices": ["enable", "disable"]},
                                                          "severity": {"required": False, "type": "str",
                                                                       "choices": ["high", "medium", "low"]},
                                                          "status": {"required": False, "type": "str",
                                                                     "choices": ["enable", "disable"]}
                                                      }},
                                   "exception": {"required": False, "type": "list",
                                                 "options": {
                                                     "address": {"required": False, "type": "str"},
                                                     "content_length": {"required": False, "type": "str",
                                                                        "choices": ["enable", "disable"]},
                                                     "header_length": {"required": False, "type": "str",
                                                                       "choices": ["enable", "disable"]},
                                                     "hostname": {"required": False, "type": "str",
                                                                  "choices": ["enable", "disable"]},
                                                     "id": {"required": True, "type": "int"},
                                                     "line_length": {"required": False, "type": "str",
                                                                     "choices": ["enable", "disable"]},
                                                     "malformed": {"required": False, "type": "str",
                                                                   "choices": ["enable", "disable"]},
                                                     "max_cookie": {"required": False, "type": "str",
                                                                    "choices": ["enable", "disable"]},
                                                     "max_header_line": {"required": False, "type": "str",
                                                                         "choices": ["enable", "disable"]},
                                                     "max_range_segment": {"required": False, "type": "str",
                                                                           "choices": ["enable", "disable"]},
                                                     "max_url_param": {"required": False, "type": "str",
                                                                       "choices": ["enable", "disable"]},
                                                     "method": {"required": False, "type": "str",
                                                                "choices": ["enable", "disable"]},
                                                     "param_length": {"required": False, "type": "str",
                                                                      "choices": ["enable", "disable"]},
                                                     "pattern": {"required": False, "type": "str"},
                                                     "regex": {"required": False, "type": "str",
                                                               "choices": ["enable", "disable"]},
                                                     "url_param_length": {"required": False, "type": "str",
                                                                          "choices": ["enable", "disable"]},
                                                     "version": {"required": False, "type": "str",
                                                                 "choices": ["enable", "disable"]}
                                                 }},
                                   "header_length": {"required": False, "type": "dict",
                                                     "options": {
                                                         "action": {"required": False, "type": "str",
                                                                    "choices": ["allow", "block"]},
                                                         "length": {"required": False, "type": "int"},
                                                         "log": {"required": False, "type": "str",
                                                                 "choices": ["enable", "disable"]},
                                                         "severity": {"required": False, "type": "str",
                                                                      "choices": ["high", "medium", "low"]},
                                                         "status": {"required": False, "type": "str",
                                                                    "choices": ["enable", "disable"]}
                                                     }},
                                   "hostname": {"required": False, "type": "dict",
                                                "options": {
                                                    "action": {"required": False, "type": "str",
                                                               "choices": ["allow", "block"]},
                                                    "log": {"required": False, "type": "str",
                                                            "choices": ["enable", "disable"]},
                                                    "severity": {"required": False, "type": "str",
                                                                 "choices": ["high", "medium", "low"]},
                                                    "status": {"required": False, "type": "str",
                                                               "choices": ["enable", "disable"]}
                                                }},
                                   "line_length": {"required": False, "type": "dict",
                                                   "options": {
                                                       "action": {"required": False, "type": "str",
                                                                  "choices": ["allow", "block"]},
                                                       "length": {"required": False, "type": "int"},
                                                       "log": {"required": False, "type": "str",
                                                               "choices": ["enable", "disable"]},
                                                       "severity": {"required": False, "type": "str",
                                                                    "choices": ["high", "medium", "low"]},
                                                       "status": {"required": False, "type": "str",
                                                                  "choices": ["enable", "disable"]}
                                                   }},
                                   "malformed": {"required": False, "type": "dict",
                                                 "options": {
                                                     "action": {"required": False, "type": "str",
                                                                "choices": ["allow", "block"]},
                                                     "log": {"required": False, "type": "str",
                                                             "choices": ["enable", "disable"]},
                                                     "severity": {"required": False, "type": "str",
                                                                  "choices": ["high", "medium", "low"]},
                                                     "status": {"required": False, "type": "str",
                                                                "choices": ["enable", "disable"]}
                                                 }},
                                   "max_cookie": {"required": False, "type": "dict",
                                                  "options": {
                                                      "action": {"required": False, "type": "str",
                                                                 "choices": ["allow", "block"]},
                                                      "log": {"required": False, "type": "str",
                                                              "choices": ["enable", "disable"]},
                                                      "max_cookie": {"required": False, "type": "int"},
                                                      "severity": {"required": False, "type": "str",
                                                                   "choices": ["high", "medium", "low"]},
                                                      "status": {"required": False, "type": "str",
                                                                 "choices": ["enable", "disable"]}
                                                  }},
                                   "max_header_line": {"required": False, "type": "dict",
                                                       "options": {
                                                           "action": {"required": False, "type": "str",
                                                                      "choices": ["allow", "block"]},
                                                           "log": {"required": False, "type": "str",
                                                                   "choices": ["enable", "disable"]},
                                                           "max_header_line": {"required": False, "type": "int"},
                                                           "severity": {"required": False, "type": "str",
                                                                        "choices": ["high", "medium", "low"]},
                                                           "status": {"required": False, "type": "str",
                                                                      "choices": ["enable", "disable"]}
                                                       }},
                                   "max_range_segment": {"required": False, "type": "dict",
                                                         "options": {
                                                             "action": {"required": False, "type": "str",
                                                                        "choices": ["allow", "block"]},
                                                             "log": {"required": False, "type": "str",
                                                                     "choices": ["enable", "disable"]},
                                                             "max_range_segment": {"required": False, "type": "int"},
                                                             "severity": {"required": False, "type": "str",
                                                                          "choices": ["high", "medium", "low"]},
                                                             "status": {"required": False, "type": "str",
                                                                        "choices": ["enable", "disable"]}
                                                         }},
                                   "max_url_param": {"required": False, "type": "dict",
                                                     "options": {
                                                         "action": {"required": False, "type": "str",
                                                                    "choices": ["allow", "block"]},
                                                         "log": {"required": False, "type": "str",
                                                                 "choices": ["enable", "disable"]},
                                                         "max_url_param": {"required": False, "type": "int"},
                                                         "severity": {"required": False, "type": "str",
                                                                      "choices": ["high", "medium", "low"]},
                                                         "status": {"required": False, "type": "str",
                                                                    "choices": ["enable", "disable"]}
                                                     }},
                                   "method": {"required": False, "type": "dict",
                                              "options": {
                                                  "action": {"required": False, "type": "str",
                                                             "choices": ["allow", "block"]},
                                                  "log": {"required": False, "type": "str",
                                                          "choices": ["enable", "disable"]},
                                                  "severity": {"required": False, "type": "str",
                                                               "choices": ["high", "medium", "low"]},
                                                  "status": {"required": False, "type": "str",
                                                             "choices": ["enable", "disable"]}
                                              }},
                                   "param_length": {"required": False, "type": "dict",
                                                    "options": {
                                                        "action": {"required": False, "type": "str",
                                                                   "choices": ["allow", "block"]},
                                                        "length": {"required": False, "type": "int"},
                                                        "log": {"required": False, "type": "str",
                                                                "choices": ["enable", "disable"]},
                                                        "severity": {"required": False, "type": "str",
                                                                     "choices": ["high", "medium", "low"]},
                                                        "status": {"required": False, "type": "str",
                                                                   "choices": ["enable", "disable"]}
                                                    }},
                                   "url_param_length": {"required": False, "type": "dict",
                                                        "options": {
                                                            "action": {"required": False, "type": "str",
                                                                       "choices": ["allow", "block"]},
                                                            "length": {"required": False, "type": "int"},
                                                            "log": {"required": False, "type": "str",
                                                                    "choices": ["enable", "disable"]},
                                                            "severity": {"required": False, "type": "str",
                                                                         "choices": ["high", "medium", "low"]},
                                                            "status": {"required": False, "type": "str",
                                                                       "choices": ["enable", "disable"]}
                                                        }},
                                   "version": {"required": False, "type": "dict",
                                               "options": {
                                                   "action": {"required": False, "type": "str",
                                                              "choices": ["allow", "block"]},
                                                   "log": {"required": False, "type": "str",
                                                           "choices": ["enable", "disable"]},
                                                   "severity": {"required": False, "type": "str",
                                                                "choices": ["high", "medium", "low"]},
                                                   "status": {"required": False, "type": "str",
                                                              "choices": ["enable", "disable"]}
                                               }}
                               }},
                "extended_log": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "external": {"required": False, "type": "str",
                             "choices": ["disable", "enable"]},
                "method": {"required": False, "type": "dict",
                           "options": {
                               "default_allowed_methods": {"required": False, "type": "str",
                                                           "choices": ["get", "post", "put",
                                                                       "head", "connect", "trace",
                                                                       "options", "delete", "others"]},
                               "log": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                               "method_policy": {"required": False, "type": "list",
                                                 "options": {
                                                     "address": {"required": False, "type": "str"},
                                                     "allowed_methods": {"required": False, "type": "str",
                                                                         "choices": ["get", "post", "put",
                                                                                     "head", "connect", "trace",
                                                                                     "options", "delete", "others"]},
                                                     "id": {"required": True, "type": "int"},
                                                     "pattern": {"required": False, "type": "str"},
                                                     "regex": {"required": False, "type": "str",
                                                               "choices": ["enable", "disable"]}
                                                 }},
                               "severity": {"required": False, "type": "str",
                                            "choices": ["high", "medium", "low"]},
                               "status": {"required": False, "type": "str",
                                          "choices": ["enable", "disable"]}
                           }},
                "name": {"required": True, "type": "str"},
                "signature": {"required": False, "type": "dict",
                              "options": {
                                  "credit_card_detection_threshold": {"required": False, "type": "int"},
                                  "custom_signature": {"required": False, "type": "list",
                                                       "options": {
                                                           "action": {"required": False, "type": "str",
                                                                      "choices": ["allow", "block", "erase"]},
                                                           "case_sensitivity": {"required": False, "type": "str",
                                                                                "choices": ["disable", "enable"]},
                                                           "direction": {"required": False, "type": "str",
                                                                         "choices": ["request", "response"]},
                                                           "log": {"required": False, "type": "str",
                                                                   "choices": ["enable", "disable"]},
                                                           "name": {"required": True, "type": "str"},
                                                           "pattern": {"required": False, "type": "str"},
                                                           "severity": {"required": False, "type": "str",
                                                                        "choices": ["high", "medium", "low"]},
                                                           "status": {"required": False, "type": "str",
                                                                      "choices": ["enable", "disable"]},
                                                           "target": {"required": False, "type": "str",
                                                                      "choices": ["arg", "arg-name", "req-body",
                                                                                  "req-cookie", "req-cookie-name", "req-filename",
                                                                                  "req-header", "req-header-name", "req-raw-uri",
                                                                                  "req-uri", "resp-body", "resp-hdr",
                                                                                  "resp-status"]}
                                                       }},
                                  "disabled_signature": {"required": False, "type": "list",
                                                         "options": {
                                                             "id": {"required": True, "type": "int"}
                                                         }},
                                  "disabled_sub_class": {"required": False, "type": "list",
                                                         "options": {
                                                             "id": {"required": True, "type": "int"}
                                                         }},
                                  "main_class": {"required": False, "type": "list",
                                                 "options": {
                                                     "action": {"required": False, "type": "str",
                                                                "choices": ["allow", "block", "erase"]},
                                                     "id": {"required": True, "type": "int"},
                                                     "log": {"required": False, "type": "str",
                                                             "choices": ["enable", "disable"]},
                                                     "severity": {"required": False, "type": "str",
                                                                  "choices": ["high", "medium", "low"]},
                                                     "status": {"required": False, "type": "str",
                                                                "choices": ["enable", "disable"]}
                                                 }}
                              }},
                "url_access": {"required": False, "type": "list",
                               "options": {
                                   "access_pattern": {"required": False, "type": "list",
                                                      "options": {
                                                          "id": {"required": True, "type": "int"},
                                                          "negate": {"required": False, "type": "str",
                                                                     "choices": ["enable", "disable"]},
                                                          "pattern": {"required": False, "type": "str"},
                                                          "regex": {"required": False, "type": "str",
                                                                    "choices": ["enable", "disable"]},
                                                          "srcaddr": {"required": False, "type": "str"}
                                                      }},
                                   "action": {"required": False, "type": "str",
                                              "choices": ["bypass", "permit", "block"]},
                                   "address": {"required": False, "type": "str"},
                                   "id": {"required": True, "type": "int"},
                                   "log": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                                   "severity": {"required": False, "type": "str",
                                                "choices": ["high", "medium", "low"]}
                               }}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_waf(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_waf(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
