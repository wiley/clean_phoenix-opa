package darwin.resources.entitlements
import data.darwin.authz.dinput

default allow = false

resource = "entitlements"

allow {
	dinput.path[1] == resource
}
