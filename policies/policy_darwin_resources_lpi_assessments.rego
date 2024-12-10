package darwin.resources.lpi_assessments

import data.darwin.authz.dinput
import data.darwin.token.get_jwt_payload
import data.darwin.token.get_api_key_header

default allow = false
  
resource = "lpi_assessments"

allow {
  dinput.method == ["POST", "GET", "PUT"][_]
  jwt_paylaod = get_jwt_payload(dinput.jwt)
  dinput.path[1] == resource
}

allow {
  dinput.method == ["POST", "GET", "PUT"][_]
  api_key = get_api_key_header()
  runtime = opa.runtime()
  api_key == runtime.env.LPI_API_KEY
}
