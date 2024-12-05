package darwin.account_user_roles_functions

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.authz.user_get_accounts
import data.darwin.token.get_jwt_payload
import future.keywords.in

get_account_user_roles_for_user(userid) = user_role {
    dinput.authorizationCache.userId == userid
    r := dinput.authorizationCache.accountRoles

	user_role = [o |
		it = r[_]
		o := {"role": it.role, "account_id": it.account.id}
	]
}

request_account_user_role(accountUserRoleId) =  user_role {
    runtime = opa.runtime()
    response = http.send({
		"method": "GET",
		"url": concat("", [runtime.env.COMPANY_API_URL, "/api/v4/account-user-roles/", accountUserRoleId]),
        "headers": {"x-api-key": runtime.env.COMPANY_API_KEY, "Content-type": "application/json"},
	})
    response.status_code == 200
    
    r := response.body
	user_role = {"id": r.id, "role": r.role, "account_id": r.accountId}
}

account_user_role_admin(userid) {
    some account_user_role in get_account_user_roles_for_user(userid)
	account_user_role.role == "Admin"
}

account_user_role_admin_and_role_id(userid, accountUserRoleId) {
    user_role_account_user_role = request_account_user_role(accountUserRoleId)
    some account_user_role in get_account_user_roles_for_user(userid)
	    account_user_role.role == "Admin"
        account_user_role.account_id == user_role_account_user_role.account_id
}