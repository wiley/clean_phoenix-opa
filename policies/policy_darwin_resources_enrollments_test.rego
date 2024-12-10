package darwin.resources.enrollments

import data.darwin.authz.dinput
import data.darwin.token.get_jwt_payload
import data.darwin.token.jwt_is_valid

import future.keywords

# Mock functions
mock_user_get_orgs(1) := [{"id": 1}]
mock_user_get_orgs(2) := [{"id": 1}]
mock_user_get_orgs(3) := [{"id": 2}]

mock_user_has_role_on_organization(["InstructionalDesigner", "OrgAdmin"], 1) := true
mock_user_has_role_on_organization(["InstructionalDesigner", "OrgAdmin"], 2) := false

mock_resources["enrollments"] := {
    "status_code": 200,
    "body": {"userId": 1, "trainingProgramId": "GUID"}
}

mock_resources_deny["enrollments"] := {
    "status_code": 200,
    "body": {"userId": 3, "trainingProgramId": "GUID"}
}
# Test cases
mock_dinput_api_key_get_allow := {"path": ["v4", "enrollments"], "method": "GET", "hasApiKey": true}
test_allow_with_api_key if {
    allow
    with data.darwin.authz.dinput as mock_dinput_api_key_get_allow
    with data.darwin.resources.enrollments.resources as mock_resources
}

mock_dinput_kafka_event_put_deny := {"path": ["v4", "enrollments", "generate-kafka-events"], "method": "PUT", "hasApiKey": false}
test_deny_kafka_event_without_api_key if {
    not allow
    with data.darwin.authz.dinput as mock_dinput_kafka_event_put_deny
    with data.darwin.resources.enrollments.resources as mock_resources
}

mock_dinput_change_enrollments_same_org := {"path": ["v4", "enrollments"], "method": "POST", "body": {"userId": 1}}
test_allow_change_enrollments_same_org if {
    allow
    with data.darwin.authz.dinput as mock_dinput_change_enrollments_same_org
    with data.darwin.authz.user_get_orgs as mock_user_get_orgs
    with data.darwin.authz.user_has_role_on_organization as mock_user_has_role_on_organization
    with data.darwin.resources.enrollments.resources as mock_resources
}

mock_dinput_change_enrollments_same_org_to_same_org := {"path": ["v4", "enrollments", "1"], "method": "PUT", "body": {"userId": 2}}
test_allow_change_enrollments_same_org_to_same_org if {
    allow
    with data.darwin.authz.dinput as mock_dinput_change_enrollments_same_org_to_same_org
    with data.darwin.authz.user_get_orgs as mock_user_get_orgs
    with data.darwin.authz.user_has_role_on_organization as mock_user_has_role_on_organization
    with data.darwin.resources.enrollments.resources as mock_resources
}

mock_dinput_enroll_other_users_same_org := {"path": ["v4", "enrollments", "2"], "method": "GET"}
test_allow_enroll_other_users_same_org if {
    allow
    with data.darwin.authz.dinput as mock_dinput_enroll_other_users_same_org
    with data.darwin.authz.user_get_orgs as mock_user_get_orgs
    with data.darwin.authz.user_has_role_on_organization as mock_user_has_role_on_organization
    with data.darwin.resources.enrollments.resources as mock_resources
}

mock_dinput_enroll_other_users_different_org := {"path": ["v4", "enrollments", "3"], "method": "GET"}
test_deny_enroll_other_users_different_org if {
    not allow
    with data.darwin.authz.dinput as mock_dinput_enroll_other_users_different_org
    with data.darwin.authz.user_get_orgs as mock_user_get_orgs
    with data.darwin.authz.user_has_role_on_organization as mock_user_has_role_on_organization
    with data.darwin.resources.enrollments.resources as mock_resources_deny
}