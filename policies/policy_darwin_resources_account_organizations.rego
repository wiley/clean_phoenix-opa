package darwin.resources.account_organizations

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.token.get_jwt_payload
import data.darwin.token.get_api_key
import future.keywords.in

default allow = false

allow {
	dinput.path[1] == "account_organizations"
}
