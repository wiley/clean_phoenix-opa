

package darwin.resources.skills_categories

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.token.get_jwt_payload
import data.darwin.token.jwt_is_valid

default allow = false

allow {
	dinput.path[1] == "skills-categories"
}
