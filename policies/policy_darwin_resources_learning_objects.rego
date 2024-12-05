package darwin.resources.learning_objects

import data.darwin.authz.dinput # always use dinput instead of input
import data.darwin.authz.user_has_role_on_organization
import data.darwin.authz.user_get_orgs
import data.darwin.token.get_jwt_payload
import data.darwin.token.jwt_is_valid
import future.keywords.in
import future.keywords.every

resource = "learning_objects"
default allow = false

# Different cases :
#		- GET / : You only have access if you have API key
#		- GET /{id} : You can use this endpoint with :
#			-	API key
#			-	You belong to organization of the learning object
#		- POST / : You can use this endpoint with :
#			-	API key
#			-	If you create a learning object that contain only organization you belong to
#		- PUT /{id} : You can use this endpoint with :
#			-	API key
#			-	You belong to organization of the learning object
#		- DELETE /{id} : You can use this endpoint with :
#			-	API key
#			-	You belong to organization of the learning object
#		- GET /search : You can use this endpoint with :
#			-	API key
#			-	You belong to organization of the learning object

# Get a resource from the training program API using the API KEY.
get_learning_object(path) = r {
	trace("Get learning object")
	runtime = opa.runtime()
	r := http.send({
		"method": "GET",
		"url": concat("", [runtime.env.CONTENTS_API_URL, "/", replace(path, "_", "-")]),
		"headers": {
			"x-api-key": runtime.env.CONTENTS_API_KEY,
			"x-user-id": "0"
		},
		"raise_error": false
	})
}

# Check if the user belong to the organization
user_belong_to_organization(userId, organizationId) {
	trace("User belong to organization")
	some org in user_get_orgs(userId)
	org.id == organizationId
}

# Retrieve organizationId from a learning object id
get_organization_ids_from_learning_object() = r {
	trace("Get organization ids from learning object")
	urlQuery := concat("/", array.slice(dinput.path, 0, 3))
	response := get_learning_object(urlQuery)
	r := response.body.organizationIds
}

# With Api key you can do everything
allow {
	trace("Allow with api key")
	dinput.method == ["GET", "POST", "PUT", "DELETE"][_]
	dinput.path[1] == resource
	dinput.hasApiKey
}

allow {
	trace("Allow for get, put and delete")
	dinput.method == ["GET", "PUT", "DELETE"][_]
	dinput.path[1] == "learning_objects"
	dinput.path[2] != ""
	organizationIds := get_organization_ids_from_learning_object()
	some organizationId in organizationIds 
	user_belong_to_organization(dinput.userId, organizationId) 
}

allow {
	trace("Allow for post")
	dinput.method == ["POST"][_]
	dinput.path[1] == "learning_objects"
	dinput.path[2] != "search"
	organizationIds := dinput.body.organizationIds
	every organizationId in organizationIds {
		user_belong_to_organization(dinput.userId, organizationId)
	} 
}

# Allow a user to search of learning object:
#   - the user is a part of the requested organization (from organizationId query parameter)
#   - the user has Learner, InstructionalDesigner or OrgAdmin role in the organization
allow {
	trace("Allow for search")
	dinput.method == ["POST"][_]
	dinput.path[1] == "learning_objects"
	dinput.path[2] == "search"
	user_has_role_on_organization(
		["Learner", "InstructionalDesigner", "OrgAdmin"],
		dinput.query.organizationId
	)
}
