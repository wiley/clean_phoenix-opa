package darwin.resources.organizations

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.token.get_jwt_payload
import data.darwin.token.get_api_key_header
import data.darwin.authz.user_get_orgs
import future.keywords.in

default authz = false
# https://www.openpolicyagent.org/docs/latest/faq/#conflict-resolution
authz {
    allow
    not deny
}

# Allow everything if you have the API Key
allow {
	trace("Allow with api key")
	dinput.method == ["GET", "POST", "PUT", "PATCH", "DELETE"][_]
	dinput.hasApiKey
}

# Deny access to kafka event initialize if you don't have API key
deny {
	trace("Deny kafka event without API Key")
	dinput.method == "PUT"
	dinput.path[2] == "generate-kafka-events"
	not dinput.hasApiKey
}

# Allow a user to read the organization if:
#   - user belongs to the same organization he is requesting
allow {
	dinput.method == "GET" 
	dinput.path[1] == "organizations"
	organizationTarget = to_number(dinput.path[2])
	jwt := get_jwt_payload(dinput.jwt)
	some userOrganization in user_get_orgs(jwt.user_id)
	userOrganization.id == organizationTarget
}
