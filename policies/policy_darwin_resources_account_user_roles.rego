package darwin.resources.account_user_roles

import data.darwin.authz.dinput # always use dinput instead of input
import future.keywords.in
import data.darwin.account_user_roles_functions.account_user_role_admin
import data.darwin.account_user_roles_functions.account_user_role_admin_and_role_id


default allow = false

allow {
	dinput.method == "POST"
	dinput.path[1] == "account_user_roles"
	trace("POST /account-user-roles")
	dinput.hasApiKey
}

allow {
	dinput.method == "GET"
	dinput.path[1] == "account_user_roles"
	accountUserRoleId = dinput.path[2]
	trace(sprintf("GET /account-user-roles/%v", [accountUserRoleId]))
	account_user_role_admin_and_role_id(dinput.userId, accountUserRoleId)
}

allow {
	dinput.method == "GET"
	dinput.path[1] == "account_user_roles"
	count(dinput.path) == 2 #test that there are no other parameters in the path
	trace("GET /account-user-roles")
	account_user_role_admin(dinput.userId)
}

allow {
	dinput.method == "DELETE"
	dinput.path[1] == "account_user_roles"
	accountUserRoleId = dinput.path[2]
	trace(sprintf("DELETE /account-user-roles/%v", [accountUserRoleId]))
	dinput.hasApiKey
}