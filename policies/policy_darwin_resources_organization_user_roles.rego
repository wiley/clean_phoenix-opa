package darwin.resources.organization_user_roles

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.authz.get_organization_user_roles_for_user
import data.darwin.authz.get_organization_user_role_by_id
import future.keywords.in

resource = "organization_user_roles"
default allow = false

allow {
	dinput.method == ["POST", "DELETE", "GET"][_]
	dinput.path[1] == resource
	dinput.hasApiKey
}

allow_get_organization_user_roles(userId, usersOrgUserRoles, organizationUserRole) {
	some usersOrgUserRole in usersOrgUserRoles
	usersOrgUserRole.role == "OrgAdmin"
	usersOrgUserRole.id == organizationUserRole.organizationId
}
allow_get_organization_user_roles(userId, usersOrgUserRoles, organizationUserRole) {
	organizationUserRole.userId == userId
}

## policy JWT User for GET by OrganizationUserRoleId
allow {
	dinput.method == "GET"
	dinput.path[1] == resource
	dinput.path[2] != ""
	organizationUserRoleId = to_number(dinput.path[2])
	trace(sprintf("From Developer: GET /organization-user-roles/%v", [organizationUserRoleId]))
	usersOrgUserRoles = get_organization_user_roles_for_user(dinput.userId)
	count(usersOrgUserRoles) != 0
	organizationUserRole = get_organization_user_role_by_id(organizationUserRoleId)
	allow_get_organization_user_roles(dinput.userId, usersOrgUserRoles, organizationUserRole)
}

## policy JWT User for GET 
allow {
	dinput.method == "GET"
	dinput.path[1] == resource
	count(dinput.path) == 2
	trace("From Developer: GET /organization-user-roles")
	usersOrgUserRoles = get_organization_user_roles_for_user(dinput.userId)
	count(usersOrgUserRoles) != 0
	usersOrgUserRoles[_].role == "OrgAdmin"
}

## policy JWT User for GET with filtered UserID
allow {
	dinput.method == "GET"
	dinput.path[1] == resource
	count(dinput.path) == 2
	trace("From Developer: GET /organization-user-roles")
	to_number(dinput.query.userId) == to_number(dinput.userId)
}