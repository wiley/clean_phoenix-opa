package darwin.resources.invitations
import data.darwin.authz.dinput

default allow = false

resource = "invitations"

allow {
	dinput.path[1] == resource
}
