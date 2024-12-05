package darwin.resources.products
import data.darwin.authz.dinput

default allow = false

resource = "products"

allow {
	dinput.path[1] == resource
}
