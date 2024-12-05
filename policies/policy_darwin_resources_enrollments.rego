package darwin.resources.enrollments

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.authz.user_get_orgs
import data.darwin.authz.user_has_role
import data.darwin.token.get_jwt_payload
import data.darwin.token.jwt_is_valid
import data.darwin.authz.user_has_role_on_organization

import future.keywords.in

default authz := false
# https://www.openpolicyagent.org/docs/latest/faq/#conflict-resolution
authz {
    allow
    not deny
}

# Get a resource from the training program API using the API KEY.
get_resource(path) = r {
	runtime = opa.runtime()
	r := http.send({
		"method": "GET",
		"url": concat("", [runtime.env.ENROLLMENTS_API_URL, "/", replace(path, "_", "-")]),
		"headers": {
			"x-api-key": runtime.env.ENROLLMENTS_API_KEY,
			"x-user-id": "0"
		},
		"raise_error": false
	})
}

# This set contains an object with all the resources requested in the endpoint.
# It contains the status_code and body for each resource, which can be used
# in the rules. Example:
#
# {
#   "enrollments": {
#     "status_code": 200,
#     "body": {"userId": "123", "trainingProgramId": "GUID"}
#   }
# }
resources[name] := resource {
	trace("resources method")
	some i in numbers.range_step(1, count(dinput.path), 2)
	dinput.path[i + 1]
	name := dinput.path[i]
	response := get_resource(concat("/", array.slice(dinput.path, 0, i + 2)))
	resource := {"status_code": response.status_code, "body": response.body}
}

# Allow all with API key
allow {
    trace("Allow everything with API key")
    dinput.path[1] == "enrollments"
    dinput.method == ["GET", "POST", "PUT", "PATCH", "DELETE"][_]
    dinput.hasApiKey
}

# Deny access to kafka event initialize if you don't have API key
deny {
    trace("Deny kafka event without API Key")
    dinput.path[1] == "enrollments"
    dinput.method == "PUT"
    dinput.path[2] == "generate-kafka-events"
    not dinput.hasApiKey
}

# Allow users to create enrollments only for users from the same organization
allow {
    trace("Allow users to create enrollments only for users from the same organization")
    dinput.path[1] == "enrollments"
    dinput.method == "POST"
    orgUser := user_get_orgs(dinput.body.userId)
    some org in orgUser
    user_has_role_on_organization(
        ["InstructionalDesigner", "OrgAdmin"],
        org.id
    )
}

# Allow users to change enrollments only for users from the same organization to the same organization
allow {
    trace("Allow users to change enrollments only for users from the same organization to the same organization")
    dinput.path[1] == "enrollments"
    dinput.method == ["PUT", "PATCH"][_]
    some fromOrg in user_get_orgs(to_number(resources.enrollments.body.userId))
    user_has_role_on_organization(
        ["InstructionalDesigner", "OrgAdmin"],
        fromOrg.id
    )
    some toOrg in user_get_orgs(dinput.body.userId)
    user_has_role_on_organization(
        ["InstructionalDesigner", "OrgAdmin"],
        toOrg.id
    )
}

# Allow users to enroll other users only if they are part of the same organization
allow {
    trace("Allow users to enroll other users only if they are part of the same organization")
    dinput.method == ["GET", "DELETE"][_]
    dinput.path[1] == "enrollments"
    dinput.path[2] != ""
    some org in user_get_orgs(to_number(resources.enrollments.body.userId))
    user_has_role_on_organization(
        ["InstructionalDesigner", "OrgAdmin"],
        org.id
    )
}

# Allow users to get other enrollment if you are an admin
allow {
    trace("Allow users to get other enrollment if you are an admin")
    dinput.method == "GET"
    dinput.path[1] == "enrollments"
    not dinput.path[2]
	user_has_role("OrgAdmin")
}

# Allow users to get other enrollment if you are an learner and asking for your own enrollment
allow {
    trace("Allow users to get other enrollment if you are an admin")
    dinput.method == "GET"
    dinput.path[1] == "enrollments"
    not dinput.path[2]
	user_has_role("Learner")
    to_number(dinput.query.userId) == dinput.userId
}