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
from ansible.module_utils.network.fortios.fortios import FortiOSHandler

try:
    from ansible.modules.network.fortios import fortios_user_device
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


def load_fixtures():
    fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures') + "/{filename}.json".format(
        filename=os.path.splitext(os.path.basename(__file__))[0])
    try:
        with open(fixture_path, "r") as fixture_file:
            fixture_data = json.load(fixture_file)
    except IOError:
        return []
    return [fixture_data]


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_user_device.Connection')
    return connection_class_mock

@pytest.fixture(scope="function", params=load_fixtures())
def fixture_data(request):
    func_name = request.function.__name__.replace("test_", "")
    return request.param.get(func_name, None)


fos_instance = FortiOSHandler(connection_mock)


def log(data):
    with open('/home/magonzalez/httpapi/ansible/trace.txt', 'a') as the_file:
        the_file.write(str(data) + "\n")


def test_user_device_filter_null_attributes(mocker):
    pass


def test_user_device_filter_foreign_attributes(mocker):
    pass


def test_user_device_creation_fails(mocker):
    pass


def test_user_device_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'user_device': {
            'category': 'none',
            'comment': 'Comment.',
            'master-device': None,
            'state': 'present',
            'alias': 'myuser',
            'mac': '00:01:04:03:ab:c3:32',
            'user': 'myuser',
            'type': 'unknown',
            'tagging': None,
            'avatar': None
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_device.fortios_user(input_data, fos_instance)

    expected_data = {
        'alias': 'myuser',
        'category': 'none',
        'comment': 'Comment.',
        'mac': '00:01:04:03:ab:c3:32',
        'type': 'unknown',
        'user': 'myuser'
    }

    set_method_mock.assert_called_with('user', 'device', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_users_device_removal(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'user_device': {
            'category': 'none',
            'comment': 'Comment.',
            'master-device': None,
            'state': 'absent',
            'alias': 'myuser',
            'mac': '00:01:04:03:ab:c3:32',
            'user': 'myuser',
            'type': 'unknown',
            'tagging': None,
            'avatar': None
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_user_device.fortios_user(input_data, fos_instance)

    delete_method_mock.assert_called_with('user', 'device', mkey='myuser', vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200