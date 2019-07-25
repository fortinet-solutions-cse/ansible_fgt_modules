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
# along with Ansible.  If not, see <https://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
import pytest
from mock import ANY
from ansible.module_utils.network.fortios.fortios import FortiOSHandler

try:
    from ansible.modules.network.fortios import fortios_user_group
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_user_group.Connection')
    return connection_class_mock


fos_instance = FortiOSHandler(connection_mock)


def test_user_group_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'user_group': {
            'auth_concurrent_override': 'enable',
            'auth_concurrent_value': '4',
            'authtimeout': '5',
            'company': 'optional',
            'email': 'disable',
            'expire': '8',
            'expire_type': 'immediately',
            'group_type': 'firewall',
            'http_digest_realm': 'test_value_11',
            'id': '12',
            'max_accounts': '13',
            'mobile_phone': 'disable',
            'multiple_guest_add': 'disable',
            'name': 'default_name_16',
            'password': 'auto-generate',
            'sms_custom_server': 'test_value_18',
            'sms_server': 'fortiguard',
            'sponsor': 'optional',
            'sso_attribute_value': 'test_value_21',
            'user_id': 'email',
            'user_name': 'disable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_group.fortios_user(input_data, fos_instance)

    expected_data = {
        'auth-concurrent-override': 'enable',
        'auth-concurrent-value': '4',
        'authtimeout': '5',
        'company': 'optional',
        'email': 'disable',
        'expire': '8',
        'expire-type': 'immediately',
        'group-type': 'firewall',
        'http-digest-realm': 'test_value_11',
        'id': '12',
        'max-accounts': '13',
        'mobile-phone': 'disable',
        'multiple-guest-add': 'disable',
        'name': 'default_name_16',
                'password': 'auto-generate',
                'sms-custom-server': 'test_value_18',
                'sms-server': 'fortiguard',
                'sponsor': 'optional',
                'sso-attribute-value': 'test_value_21',
                'user-id': 'email',
                'user-name': 'disable'
    }

    set_method_mock.assert_called_with('user', 'group', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_user_group_creation_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'user_group': {
            'auth_concurrent_override': 'enable',
            'auth_concurrent_value': '4',
            'authtimeout': '5',
            'company': 'optional',
            'email': 'disable',
            'expire': '8',
            'expire_type': 'immediately',
            'group_type': 'firewall',
            'http_digest_realm': 'test_value_11',
            'id': '12',
            'max_accounts': '13',
            'mobile_phone': 'disable',
            'multiple_guest_add': 'disable',
            'name': 'default_name_16',
            'password': 'auto-generate',
            'sms_custom_server': 'test_value_18',
            'sms_server': 'fortiguard',
            'sponsor': 'optional',
            'sso_attribute_value': 'test_value_21',
            'user_id': 'email',
            'user_name': 'disable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_group.fortios_user(input_data, fos_instance)

    expected_data = {
        'auth-concurrent-override': 'enable',
        'auth-concurrent-value': '4',
        'authtimeout': '5',
        'company': 'optional',
        'email': 'disable',
        'expire': '8',
        'expire-type': 'immediately',
        'group-type': 'firewall',
        'http-digest-realm': 'test_value_11',
        'id': '12',
        'max-accounts': '13',
        'mobile-phone': 'disable',
        'multiple-guest-add': 'disable',
        'name': 'default_name_16',
                'password': 'auto-generate',
                'sms-custom-server': 'test_value_18',
                'sms-server': 'fortiguard',
                'sponsor': 'optional',
                'sso-attribute-value': 'test_value_21',
                'user-id': 'email',
                'user-name': 'disable'
    }

    set_method_mock.assert_called_with('user', 'group', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_user_group_removal(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'user_group': {
            'auth_concurrent_override': 'enable',
            'auth_concurrent_value': '4',
            'authtimeout': '5',
            'company': 'optional',
            'email': 'disable',
            'expire': '8',
            'expire_type': 'immediately',
            'group_type': 'firewall',
            'http_digest_realm': 'test_value_11',
            'id': '12',
            'max_accounts': '13',
            'mobile_phone': 'disable',
            'multiple_guest_add': 'disable',
            'name': 'default_name_16',
            'password': 'auto-generate',
            'sms_custom_server': 'test_value_18',
            'sms_server': 'fortiguard',
            'sponsor': 'optional',
            'sso_attribute_value': 'test_value_21',
            'user_id': 'email',
            'user_name': 'disable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_group.fortios_user(input_data, fos_instance)

    delete_method_mock.assert_called_with('user', 'group', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_user_group_deletion_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'user_group': {
            'auth_concurrent_override': 'enable',
            'auth_concurrent_value': '4',
            'authtimeout': '5',
            'company': 'optional',
            'email': 'disable',
            'expire': '8',
            'expire_type': 'immediately',
            'group_type': 'firewall',
            'http_digest_realm': 'test_value_11',
            'id': '12',
            'max_accounts': '13',
            'mobile_phone': 'disable',
            'multiple_guest_add': 'disable',
            'name': 'default_name_16',
            'password': 'auto-generate',
            'sms_custom_server': 'test_value_18',
            'sms_server': 'fortiguard',
            'sponsor': 'optional',
            'sso_attribute_value': 'test_value_21',
            'user_id': 'email',
            'user_name': 'disable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_group.fortios_user(input_data, fos_instance)

    delete_method_mock.assert_called_with('user', 'group', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_user_group_idempotent(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'DELETE', 'http_status': 404}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'user_group': {
            'auth_concurrent_override': 'enable',
            'auth_concurrent_value': '4',
            'authtimeout': '5',
            'company': 'optional',
            'email': 'disable',
            'expire': '8',
            'expire_type': 'immediately',
            'group_type': 'firewall',
            'http_digest_realm': 'test_value_11',
            'id': '12',
            'max_accounts': '13',
            'mobile_phone': 'disable',
            'multiple_guest_add': 'disable',
            'name': 'default_name_16',
            'password': 'auto-generate',
            'sms_custom_server': 'test_value_18',
            'sms_server': 'fortiguard',
            'sponsor': 'optional',
            'sso_attribute_value': 'test_value_21',
            'user_id': 'email',
            'user_name': 'disable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_group.fortios_user(input_data, fos_instance)

    expected_data = {
        'auth-concurrent-override': 'enable',
        'auth-concurrent-value': '4',
        'authtimeout': '5',
        'company': 'optional',
        'email': 'disable',
        'expire': '8',
        'expire-type': 'immediately',
        'group-type': 'firewall',
        'http-digest-realm': 'test_value_11',
        'id': '12',
        'max-accounts': '13',
        'mobile-phone': 'disable',
        'multiple-guest-add': 'disable',
        'name': 'default_name_16',
                'password': 'auto-generate',
                'sms-custom-server': 'test_value_18',
                'sms-server': 'fortiguard',
                'sponsor': 'optional',
                'sso-attribute-value': 'test_value_21',
                'user-id': 'email',
                'user-name': 'disable'
    }

    set_method_mock.assert_called_with('user', 'group', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 404


def test_user_group_filter_foreign_attributes(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'user_group': {
            'random_attribute_not_valid': 'tag',
            'auth_concurrent_override': 'enable',
            'auth_concurrent_value': '4',
            'authtimeout': '5',
            'company': 'optional',
            'email': 'disable',
            'expire': '8',
            'expire_type': 'immediately',
            'group_type': 'firewall',
            'http_digest_realm': 'test_value_11',
            'id': '12',
            'max_accounts': '13',
            'mobile_phone': 'disable',
            'multiple_guest_add': 'disable',
            'name': 'default_name_16',
            'password': 'auto-generate',
            'sms_custom_server': 'test_value_18',
            'sms_server': 'fortiguard',
            'sponsor': 'optional',
            'sso_attribute_value': 'test_value_21',
            'user_id': 'email',
            'user_name': 'disable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_group.fortios_user(input_data, fos_instance)

    expected_data = {
        'auth-concurrent-override': 'enable',
        'auth-concurrent-value': '4',
        'authtimeout': '5',
        'company': 'optional',
        'email': 'disable',
        'expire': '8',
        'expire-type': 'immediately',
        'group-type': 'firewall',
        'http-digest-realm': 'test_value_11',
        'id': '12',
        'max-accounts': '13',
        'mobile-phone': 'disable',
        'multiple-guest-add': 'disable',
        'name': 'default_name_16',
                'password': 'auto-generate',
                'sms-custom-server': 'test_value_18',
                'sms-server': 'fortiguard',
                'sponsor': 'optional',
                'sso-attribute-value': 'test_value_21',
                'user-id': 'email',
                'user-name': 'disable'
    }

    set_method_mock.assert_called_with('user', 'group', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200
