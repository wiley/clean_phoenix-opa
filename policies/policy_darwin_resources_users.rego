package darwin.resources.users

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.authz.user_get_orgs
import data.darwin.token.get_jwt_payload
import future.keywords.in
import future.keywords.if
import data.darwin.authz.user_has_role

default authz = false
# https://www.openpolicyagent.org/docs/latest/faq/#conflict-resolution
authz {
    allow
    not deny
}

#users can create users if they are admin
user_can_create_user(from) {
	some org in user_get_orgs(from)
	org.role == "OrgAdmin"
}

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

allow {
	dinput.method == "POST"
	dinput.path[1] == "users"
	user_can_create_user(dinput.userId)
}

#user can edit users in their organization if they are admin
user_can_edit_user(from, to) {
	some org in user_get_orgs(from)
	org.role == "OrgAdmin"
	some orgTo in user_get_orgs(to)
	orgTo.id == org.id
}

#users can edit themselves
user_can_edit_user(from, to) {
	from == to
}

allow {
	dinput.method == ["POST", "PUT", "PATCH"][_]
	dinput.path[1] == "users"
	jwt = get_jwt_payload(dinput.jwt)
	target = to_number(dinput.path[2])
	user_can_edit_user(jwt.user_id, target)
}

allow {
	dinput.method == ["POST"][_]
	dinput.path[1] == "users"
	dinput.path[2] == "search"
	user_has_role("InstructionalDesigner")
}

allow {
	dinput.method == ["POST"][_]
	dinput.path[1] == "users"
	dinput.path[2] == "search"
	user_has_role("OrgAdmin")
}

#user can read users in their organization
user_can_read_user(from, to) {
	some org in user_get_orgs(from)
	some orgTo in user_get_orgs(to)
	orgTo.id == org.id
}

#users can read themselves
user_can_read_user(from, to) {
	from == to
}

allow {
	dinput.method == ["GET"][_]
	dinput.path[1] == "users"
	jwt = get_jwt_payload(dinput.jwt)
	target = to_number(dinput.path[2])
	user_can_read_user(jwt.user_id, target)
}

allow {
  dinput.method == ["POST"][_]
  dinput.path[2] == "logout"
}
