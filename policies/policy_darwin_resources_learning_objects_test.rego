package darwin.resources.learning_objects

import future.keywords

# First parameter : roles
# Second parameter : organization_id
mock_user_has_role_on_organization_search(_, 1) := true
mock_user_has_role_on_organization_search(_, x) := false if x != 1

# First parameter : user_id
# Second parameter : organization_id
mock_user_belong_to_organization(2, 1) := true
mock_user_belong_to_organization(2, 2) := true
mock_user_belong_to_organization(2, 3) := false

mock_get_learning_object_allow("v4/learning_objects/1") := {"body" : {"organizationIds" : [1, 2, 3]}}

mock_dinput_api_key_get_allow := {"path" : ["v4", "learning_objects"], "method" : "GET", "hasApiKey" : true}
test_api_key_get_allow if {
	allow 
    with data.darwin.authz.dinput as mock_dinput_api_key_get_allow
}

mock_dinput_api_key_post_allow := {"path" : ["v4", "learning_objects"], "method" : "POST", "hasApiKey" : true}
test_api_key_post_allow if {
	allow 
    with data.darwin.authz.dinput as mock_dinput_api_key_post_allow
}

mock_dinput_api_key_put_allow := {"path" : ["v4", "learning_objects"], "method" : "PUT", "hasApiKey" : true}
test_api_key_put_allow if {
	allow 
    with data.darwin.authz.dinput as mock_dinput_api_key_put_allow
}

mock_dinput_api_key_delete_allow := {"path" : ["v4", "learning_objects"], "method" : "DELETE", "hasApiKey" : true}
test_api_key_delete_allow if {
	allow 
    with data.darwin.authz.dinput as mock_dinput_api_key_delete_allow
}

mock_dinput_api_key_patch_not_allow := {"path" : ["v4", "learning_objects"], "method" : "PATCH", "hasApiKey" : true}
test_api_key_patch_not_allow if {
	not allow 
    with data.darwin.authz.dinput as mock_dinput_api_key_patch_not_allow
}

mock_dinput_api_key_not_allow := {"path" : ["v4", "learning_objects"], "hasApiKey" : false}
test_api_key_allow if {
	not allow 
    with data.darwin.authz.dinput as mock_dinput_api_key_not_allow
}

mock_dinput_get_allow := {"path" : ["v4", "learning_objects", "1"], "userId" : 2, "method" : "GET", "query": {"organizationId" : 1}}
test_get_allow if {
	allow 
    with data.darwin.authz.dinput as mock_dinput_get_allow
    with data.darwin.resources.learning_objects.get_learning_object as mock_get_learning_object_allow
    with data.darwin.resources.learning_objects.user_belong_to_organization as mock_user_belong_to_organization
}

mock_dinput_post_allow := {"path" : ["v4", "learning_objects", "1"], "userId" : 2, "method" : "POST", "body": {"organizationIds" : [1, 2]}}
test_post_allow if {
	allow 
    with data.darwin.authz.dinput as mock_dinput_post_allow
    with data.darwin.resources.learning_objects.user_belong_to_organization as mock_user_belong_to_organization
}

mock_dinput_post_not_allow := {"path" : ["v4", "learning_objects", "1"], "userId" : 2, "method" : "POST", "body": {"organizationIds" : [1, 2, 3]}}
test_post_not_allow if {
	not allow 
    with data.darwin.authz.dinput as mock_dinput_post_not_allow
    with data.darwin.resources.learning_objects.user_belong_to_organization as mock_user_belong_to_organization
}

mock_dinput_search_allow := {"path" : ["v4", "learning_objects", "search"], "method" : "POST", "query": {"organizationId" : 1}}
test_search_allow if {
	allow 
    with data.darwin.authz.dinput as mock_dinput_search_allow
    with data.darwin.authz.user_has_role_on_organization as mock_user_has_role_on_organization_search
}

mock_dinput_search_not_allow := {"path" : ["v4", "learning_objects", "search"], "method" : "POST", "query": {"organizationId" : 2}}
test_search_not_allow if {
	not allow 
    with data.darwin.authz.dinput as mock_dinput_search_not_allow
    with data.darwin.authz.user_has_role_on_organization as mock_user_has_role_on_organization_search
}