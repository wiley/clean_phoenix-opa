package darwin.resources.accounts

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.token.get_jwt_payload
import data.darwin.token.get_api_key
import future.keywords.in

default allow = false

allow {
	dinput.method == "POST"
	dinput.path[1] == "accounts"
	trace("POST /accounts")
}

allow {
	dinput.method == ["PUT", "PATCH"][_]
	dinput.path[1] == "accounts"
	target = to_number(dinput.path[2])
	trace("PUT /accounts/{accountId}")
}

allow {
	dinput.method == "GET"
	dinput.path[1] == "accounts"
	target = to_number(dinput.path[2])
	trace(sprintf("GET /accounts/{%v}", [target]))
}

allow {
	dinput.method == "GET"
	dinput.path[1] == "accounts"
	count(dinput.path) == 2 #test that there are no other parameters in the path
	trace("GET /accounts")
}
