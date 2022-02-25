"""
    Integration Tests for vmc_security_groups state module
"""
import json

import pytest
import requests
from saltext.vmware.utils import vmc_request

from tests.integration.conftest import get_config


@pytest.fixture()
def security_groups_test_data():
    domain_id = "cgw"
    security_group_id = "Integration_SG_1"
    updated_display_name = "Updated_SG_NAME"
    updated_tags = [{"tag": "tag1", "scope": "scope1"}]
    return domain_id, security_group_id, updated_display_name, updated_tags


@pytest.fixture
def delete_security_group(vmc_nsx_connect, security_groups_test_data):
    """
    Sets up test requirements:
    Queries vmc api for security groups
    Deletes security group if exists
    """
    hostname, refresh_key, authorization_host, org_id, sddc_id, verify_ssl, cert = vmc_nsx_connect
    domain_id, security_group_id, updated_display_name, updated_tags = security_groups_test_data

    url = (
        "https://{hostname}/vmc/reverse-proxy/api/orgs/{org_id}/sddcs/{sddc_id}/"
        "policy/api/v1/infra/domains/{domain_id}/groups"
    )
    api_url = url.format(hostname=hostname, org_id=org_id, sddc_id=sddc_id, domain_id=domain_id)
    session = requests.Session()
    headers = vmc_request.get_headers(refresh_key, authorization_host)

    response = session.get(url=api_url, verify=cert if verify_ssl else False, headers=headers)
    response.raise_for_status()
    security_rules_dict = response.json()
    if security_rules_dict["result_count"] != 0:
        results = security_rules_dict["results"]
        for result in results:
            if result["id"] == security_group_id:
                url = (
                    "https://{hostname}/vmc/reverse-proxy/api/orgs/{org_id}/sddcs/{sddc_id}/"
                    "policy/api/v1/infra/domains/{domain_id}/groups/{security_group_id}"
                )

                api_url = url.format(
                    hostname=hostname,
                    org_id=org_id,
                    sddc_id=sddc_id,
                    domain_id=domain_id,
                    security_group_id=security_group_id,
                )
                response = session.delete(
                    url=api_url, verify=cert if verify_ssl else False, headers=headers
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
