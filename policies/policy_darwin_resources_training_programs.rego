package darwin.resources.training_programs

import data.darwin.authz.dinput
import data.darwin.authz.user_has_role_on_organization
import data.darwin.authz.user_is_assigned_to_training_program
import data.darwin.token.get_api_key_header
import future.keywords.every
import future.keywords.in

default authz = false
# https://www.openpolicyagent.org/docs/latest/faq/#conflict-resolution
authz {
    allow
    not deny
}

# Get a resource from the training program API using the API KEY.
get_resource(path) = r {
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

# This set contains an object with all the resources requested in the endpoint.
# It contains the status_code and body for each resource, which can be used
# in the rules. Example:
#
# {
#   "training_programs": {
#     "status_code": 200,
#     "body": {"title": "Some Title", "description": "Some description."}
#   }
# }
resources[name] := resource {
	trace("resources method")
	some i in numbers.range_step(1, count(dinput.path), 2)
	dinput.path[i + 1]
	name := dinput.path[i]
	response := get_resource(concat("/", array.slice(dinput.path, 0, i + 2)))
	resource := {"status_code": response.status_code, "body": response.body}
}

# Allow everything if you have the API Key
allow {
	trace("Allow with api key")
	dinput.method == ["GET", "POST", "PUT", "DELETE"][_]
	dinput.hasApiKey
}

# Deny access to kafka event initialize if you don't have API key
deny {
	trace("Deny kafka event without API Key")
	dinput.method == "PUT"
	dinput.path[2] == "generate-kafka-events"
	not dinput.hasApiKey
}

# Allow access to the list of training programs if neither the required
# parameters are provided, so the API can return a Bad Request response.
allow {
	dinput.method == "GET"
	not resources.training_programs
	not dinput.query.organizationId
}

# Allow access to the endpoint if any of the provided resources
# does not exist, so the API can return a Not Found response.
allow {
	resources.training_programs
	some resource in resources
	resource.status_code != 200
}

# Allow a user to get a list of training programs:
#   - the user is a part of the requested organization (from organizationId query parameter)
#   - the user has Learner, InstructionalDesigner or OrgAdmin role in the organization
allow {
	dinput.method == "GET"
	not resources.training_programs
	user_has_role_on_organization(
		["Learner", "InstructionalDesigner", "OrgAdmin"],
		dinput.query.organizationId
	)
}

# Allow a user to read a training program if:
#   - user belongs in any organization of the requested training program
#   - user has InstructionalDesigner or OrgAdmin role
allow {
	dinput.method == "GET"
	resources.training_programs.status_code == 200
	some organization_id in resources.training_programs.body.organizationIds
	user_has_role_on_organization(
		["InstructionalDesigner", "OrgAdmin"],
		organization_id
	)
}

# Allow a user to read a training program if:
#   - user belongs in any organization of the requested training program
#   - user has Learner role
#   - user is assigned to the requested training program
allow {
	dinput.method == "GET"
	resources.training_programs.status_code == 200
	user_is_assigned_to_training_program(
		dinput.userId,
		resources.training_programs.body.id
	)
	some organization_id in resources.training_programs.body.organizationIds
	user_has_role_on_organization(
		["Learner"],
		organization_id
	)
}

# Allow a user to update data inside a training program if:
#   - user belongs in all organizations from the requested training program
#   - user has InstructionalDesigner or OrgAdmin role
allow {
	dinput.method == ["POST", "PATCH", "PUT", "DELETE"][_]
	count(resources) > 0
	count(dinput.path) > 3
	resources.training_programs.status_code == 200
	every organization_id in resources.training_programs.body.organizationIds {
		user_has_role_on_organization(
			["InstructionalDesigner", "OrgAdmin"],
			organization_id
		)
	}
}

# Allow a user to create a new training program if:
#   - user belongs in all organizations that they are trying to create the training program
#   - user has InstructionalDesigner or OrgAdmin role on the organizations
allow {
	dinput.method == "POST"
	not resources.training_programs
	every organization_id in dinput.body.organizationIds {
		user_has_role_on_organization(
			["InstructionalDesigner", "OrgAdmin"],
			organization_id
		)
	}
}

# Allow a user to update a training program metadata if:
#   - user belongs in all organizations from the training program they are trying to update
#   - user belongs in all organizations that they are trying to update in the training program
#   - user has InstructionalDesigner or OrgAdmin role on the organizations
allow {
	dinput.method == "PUT"
	count(resources) == 1
	resources.training_programs.status_code == 200
	every organization_id in resources.training_programs.body.organizationIds {
		user_has_role_on_organization(
			["InstructionalDesigner", "OrgAdmin"],
			organization_id
		)
	}
	every organization_id in dinput.body.organizationIds {
		user_has_role_on_organization(
			["InstructionalDesigner", "OrgAdmin"],
			organization_id
		)
	}
}

# Allow a user to delete a training program if:
#   - user belongs in all organizations from the training program they are trying to delete
#   - user has InstructionalDesigner or OrgAdmin role on the organizations
allow {
	dinput.method == "DELETE"
	count(resources) == 1
	resources.training_programs.status_code == 200
	every organization_id in resources.training_programs.body.organizationIds {
		user_has_role_on_organization(
			["InstructionalDesigner", "OrgAdmin"],
			organization_id
		)
	}
}

# Allow read/write access if api key is valid
allow {
	runtime = opa.runtime()
	get_api_key_header() == runtime.env.CONTENTS_API_KEY
}
