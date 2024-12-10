package darwin.resources.lpi_reports

import data.darwin.authz.dinput
import data.darwin.token.get_jwt_payload
import data.darwin.token.get_api_key_header

default allow = false

resource = "lpi_reports"

# Allow to get or the reports based on user from JWT
allow {
  dinput.method == ["GET"][_]
  jwt_paylaod = get_jwt_payload(dinput.jwt)
  dinput.path[1] == resource
}

allow {
  dinput.method == ["GET"][_]
  api_key = get_api_key_header()
  runtime = opa.runtime()
  api_key == runtime.env.LPI_API_KEY
}
