"""
    Integration Tests for vmc_org_users execution module
"""
import json

import pytest


@pytest.fixture
def vmc_common_data(vmc_connect):
    data = vmc_connect.copy()
    data.pop("sddc_id")
    data.pop("vcenter_hostname")
    data["hostname"] = vmc_connect["authorization_host"]
    data.pop("authorization_host")
    return data


def test_org_users_smoke_test(salt_call_cli, vmc_common_data):
    # get the org users list
    ret = salt_call_cli.run("vmc_org_users.list", **vmc_common_data)
    result_as_json = ret.json
    assert "error" not in result_as_json

    # Invite a new user to the org
    user_names = ["test@vmware.com"]
    organization_roles = [
        {"name": "org_member"},
        {"name": "developer"},
    ]
    ret = salt_call_cli.run(
        "vmc_org_users.invite",
        user_names=user_names,
        organization_roles=organization_roles,
        **vmc_common_data,
    )
    result_as_json = ret.json
    assert "error" not in result_as_json

    # search the user
    ret = salt_call_cli.run(
        "vmc_org_users.search", user_search_term="test@vmware.com", **vmc_common_data
    )
    result_as_json = ret.json
    assert "error" not in result_as_json
    assert result_as_json["results"] == []

    # remove the user from org
    user_ids = ["vmware.com:test-123"]
    ret = salt_call_cli.run("vmc_org_users.remove", user_ids=user_ids, **vmc_common_data)
    result_as_json = ret.json
    assert "error" not in result_as_json
    assert result_as_json["succeeded"] == []
    assert result_as_json["failed"] == user_ids
