package darwin.resources.trackings
import data.darwin.authz.dinput

default allow = false

resource = "trackings"

allow {
	dinput.path[1] == resource
}
