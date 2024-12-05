package darwin.token

import data.darwin.authz.dinput

jwks_request(url) = http.send({
	"url": url,
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 3600, # Cache response for an hour
})

default jwt_is_valid(token) = false

#keycloak validation
jwt_is_valid(token) {
	#TODO extract issuer form jwt first
	runtime = opa.runtime()

	jwks = jwks_request(concat("", [runtime.env.KEYCLOAK_URL, "/realms/phoenix/protocol/openid-connect/certs"])).body

	verified = io.jwt.verify_rs256(token, json.marshal(jwks))
	trace("...jwt valid")
}

get_jwt_payload(token) = jwt {
	jwt_is_valid(token)
	[_, jwt, _] := io.jwt.decode(token)
}

get_api_key_header() = h {
	h = dinput.headers["x-api-key"]
}

has_api_key_header {
	dinput.headers["x-api-key"] != ""
}

get_user_id_header() = u {
	u = dinput.headers["x-user-id"]
}

has_user_id_header {
	dinput.headers["x-user-id"] != ""
}
