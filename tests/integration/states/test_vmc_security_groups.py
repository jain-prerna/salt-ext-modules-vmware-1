"""
    Integration Tests for vmc_security_groups state module
"""
import json

import pytest
import requests
from saltext.vmware.utils import vmc_request


@pytest.fixture()
def security_groups_test_data():
    domain_id = "cgw"
    security_group_id = "Integration_SG_1"
    updated_display_name = "Updated_SG_NAME"
    updated_tags = [{"tag": "tag1", "scope": "scope1"}]
    return domain_id, security_group_id, updated_display_name, updated_tags


@pytest.fixture
def request_headers(common_data):
    return vmc_request.get_headers(common_data["refresh_key"], common_data["authorization_host"])


@pytest.fixture
def security_group_url(common_data):
    url = (
        "https://{hostname}/vmc/reverse-proxy/api/orgs/{org_id}/sddcs/{sddc_id}/"
        "policy/api/v1/infra/domains/{domain_id}/groups/{security_group_id}"
    )
    api_url = url.format(
        hostname=common_data["hostname"],
        org_id=common_data["org_id"],
        sddc_id=common_data["sddc_id"],
        domain_id=common_data["domain_id"],
        security_group_id=common_data["security_group_id"],
    )
    return api_url


@pytest.fixture
def security_groups_list_url(common_data):
    url = (
        "https://{hostname}/vmc/reverse-proxy/api/orgs/{org_id}/sddcs/{sddc_id}/"
        "policy/api/v1/infra/domains/{domain_id}/groups"
    )
    api_url = url.format(
        hostname=common_data["hostname"],
        org_id=common_data["org_id"],
        sddc_id=common_data["sddc_id"],
        domain_id=common_data["domain_id"],
    )
    return api_url


@pytest.fixture
def common_data(vmc_nsx_connect):
    hostname, refresh_key, authorization_host, org_id, sddc_id, verify_ssl, cert = vmc_nsx_connect
    data = {
        "hostname": hostname,
        "refresh_key": refresh_key,
        "authorization_host": authorization_host,
        "org_id": org_id,
        "sddc_id": sddc_id,
        "domain_id": "cgw",
        "security_group_id": "Integration_SG_1",
        "verify_ssl": verify_ssl,
        "cert": cert,
    }
    yield data


@pytest.fixture
def get_security_groups(common_data, security_groups_list_url, request_headers):
    session = requests.Session()
    response = session.get(
        url=security_groups_list_url,
        verify=common_data["cert"] if common_data["verify_ssl"] else False,
        headers=request_headers,
    )
    response.raise_for_status()
    return response.json()


@pytest.fixture
def delete_security_group(get_security_groups, security_group_url, request_headers, common_data):
    """
    Sets up test requirements:
    Queries vmc api for security groups
    Deletes security group if exists
    """

    for result in get_security_groups.get("results", []):
        if result["id"] == common_data["security_group_id"]:
            session = requests.Session()
            response = session.delete(
                url=security_group_url,
                verify=common_data["cert"] if common_data["verify_ssl"] else False,
                headers=request_headers,
            )
            # raise error if any
            response.raise_for_status()


def test_vmc_security_groups_state_module(
    salt_call_cli, delete_security_group, vmc_nsx_connect, security_groups_test_data
):
    # Invoke present state to create security group
    hostname, refresh_key, authorization_host, org_id, sddc_id, verify_ssl, cert = vmc_nsx_connect
    domain_id, security_group_id, updated_display_name, updated_tags = security_groups_test_data

    response = salt_call_cli.run(
        "state.single",
        "vmc_security_groups.present",
        name="present",
        hostname=hostname,
        refresh_key=refresh_key,
        authorization_host=authorization_host,
        org_id=org_id,
        sddc_id=sddc_id,
        domain_id=domain_id,
        security_group_id=security_group_id,
        verify_ssl=verify_ssl,
        cert=cert,
    )
    response_json = response.json
    result = list(response_json.values())[0]
    changes = result["changes"]

    assert changes["old"] is None
    assert changes["new"]["id"] == security_group_id
    assert result["comment"] == "Created Security group {}".format(security_group_id)

    # Test present to update with identical fields
    response = salt_call_cli.run(
        "state.single",
        "vmc_security_groups.present",
        name="present",
        hostname=hostname,
        refresh_key=refresh_key,
        authorization_host=authorization_host,
        org_id=org_id,
        sddc_id=sddc_id,
        domain_id=domain_id,
        security_group_id=security_group_id,
        verify_ssl=verify_ssl,
        cert=cert,
    )
    response_json = response.json
    result = list(response_json.values())[0]
    changes = result["changes"]
    # assert no changes are done
    assert changes == {}
    assert result["comment"] == "Security group exists already, no action to perform"

    # Invoke present state to update security group with new display_name
    response = salt_call_cli.run(
        "state.single",
        "vmc_security_groups.present",
        name="present",
        hostname=hostname,
        refresh_key=refresh_key,
        authorization_host=authorization_host,
        org_id=org_id,
        sddc_id=sddc_id,
        domain_id=domain_id,
        security_group_id=security_group_id,
        verify_ssl=verify_ssl,
        cert=cert,
        display_name=updated_display_name,
    )
    response_json = response.json
    result = list(response_json.values())[0]
    changes = result["changes"]

    assert changes["old"]["display_name"] != changes["new"]["display_name"]
    assert changes["new"]["display_name"] == updated_display_name
    assert result["comment"] == "Updated Security group {}".format(security_group_id)

    # Invoke present state to update security group with tags field
    response = salt_call_cli.run(
        "state.single",
        "vmc_security_groups.present",
        name="present",
        hostname=hostname,
        refresh_key=refresh_key,
        authorization_host=authorization_host,
        org_id=org_id,
        sddc_id=sddc_id,
        domain_id=domain_id,
        security_group_id=security_group_id,
        verify_ssl=verify_ssl,
        cert=cert,
        tags=updated_tags,
    )
    response_json = response.json
    result = list(response_json.values())[0]
    changes = result["changes"]

    assert changes["new"]["tags"] == updated_tags
    assert result["comment"] == "Updated Security group {}".format(security_group_id)

    # Invoke absent to delete the security group
    response = salt_call_cli.run(
        "state.single",
        "vmc_security_groups.absent",
        name="absent",
        hostname=hostname,
        refresh_key=refresh_key,
        authorization_host=authorization_host,
        org_id=org_id,
        sddc_id=sddc_id,
        domain_id=domain_id,
        security_group_id=security_group_id,
        verify_ssl=verify_ssl,
        cert=cert,
    )
    response_json = response.json
    result = list(response_json.values())[0]
    changes = result["changes"]

    assert changes["new"] is None
    assert changes["old"]["id"] == security_group_id
    assert result["comment"] == "Deleted Security group {}".format(security_group_id)

    # Invoke absent when security group is not present
    response = salt_call_cli.run(
        "state.single",
        "vmc_security_groups.absent",
        name="absent",
        hostname=hostname,
        refresh_key=refresh_key,
        authorization_host=authorization_host,
        org_id=org_id,
        sddc_id=sddc_id,
        domain_id=domain_id,
        security_group_id=security_group_id,
        verify_ssl=verify_ssl,
        cert=cert,
    )
    response_json = response.json
    result = list(response_json.values())[0]
    changes = result["changes"]
    # assert no changes are done
    assert changes == {}
    assert result["comment"] == "No Security group found with Id {}".format(security_group_id)
