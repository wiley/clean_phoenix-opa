package darwin.resources.recommendations
import data.darwin.authz.dinput

default allow = false

resource = "recommendations"

allow {
	dinput.path[1] == resource
}

