package darwin.authz

import data.darwin.token.get_jwt_payload
import future.keywords.in


group_get(groupid) = g {
    runtime = opa.runtime()
    params = urlquery.encode_object({"include": "members"})
    value = http.send({
        "method": "GET",
        "url": concat("", [runtime.env.GROUPS_API_URL, "/api/v1/groups/", format_int(groupid, 10), "?", params]),
        "headers": {"GroupsAPIToken": runtime.env.GROUPS_API_KEY, "Content-type": "application/json"},
    })

    g = value.body
}

get_organization_user_role_by_id(organizationUserRoleId) = r {
    runtime = opa.runtime()
    value = http.send({
        "method": "GET",
        "url": concat("", [runtime.env.COMPANY_API_URL, "/api/v4/organization-user-roles/", format_int(organizationUserRoleId, 10)]),
        "headers": {"x-api-key": runtime.env.COMPANY_API_KEY, "x-user-id": "0", "Content-type": "application/json"},
    })

    r = value.body
}

get_organization_user_roles_for_user(userid) = user_role {
    dinput.authorizationCache.userId == userid
    r := dinput.authorizationCache.organizationRoles

    user_role = [o |
        it = r[_]
        o := {"id": it.organization.id, "role": it.role}
    ]
}

default get_learner_organization_id(userId) = 0 #use zero if no learner organization found

get_learner_organization_id(userId) = i {
    runtime = opa.runtime()
    value = http.send({
        "method": "GET",
        "url": concat("", [runtime.env.COMPANY_API_URL, "/api/v4/organization-user-roles/?userId=", format_int(userId, 10), "&organizationRole=Learner"]),
        "headers": {"x-api-key": runtime.env.COMPANY_API_KEY, "x-user-id": "0", "Content-type": "application/json"},
    })

    #items could be empty, or it should have only one record
    count(value.body.items) == 1
    trace(sprintf("learner orgid = %v", [value.body.items[0].organizationId]))
    i = value.body.items[0].organizationId
}


user_authorization_cache(userId) = r {
    runtime = opa.runtime()
    value = http.send({
        "method": "GET",
        "url": concat("", [runtime.env.AUTHORIZATION_API_URL, "/v4/authz/users/", format_int(userId, 10)]),
        "headers": {"x-api-key": runtime.env.AUTHORIZATION_API_KEY},
        "raise_error": false
    })
    value.status_code == 200
    r := value.body
}

user_get_orgs(userId) = orgs {
    runtime = opa.runtime()
    value = http.send({
        "method": "GET",
        "url": concat("", [runtime.env.AUTHORIZATION_API_URL, "/v4/authz/users/", format_int(userId, 10)]),
        "headers": {"x-api-key": runtime.env.AUTHORIZATION_API_KEY},
        "raise_error": false
    })
    value.status_code == 200
    r := value.body.organizationRoles
    orgs = [o |
        it = r[_]
        o := {"id": it.organization.id, "role": it.role}
    ]
}

user_get_groups(userId) = groups {
    runtime = opa.runtime()
    search = urlquery.encode_object({"memberID": format_int(userId, 10), "memberType": "All", "type": "1", "visibility": "All"})
    value = http.send({
        "method": "GET",
        "url": concat("", [runtime.env.GROUPS_API_URL, "/api/v1/groups/search?", search]),
        "headers": {"GroupsAPIToken": runtime.env.GROUPS_API_KEY, "Content-type": "application/json"},
    })

    r := value.body.content
    gg = [group |
        groupid = r[_].groupID
        g := group_get(groupid)
        member := g.members[_]
        member.memberID == userId
        group := {"id": groupid, "groupType": g.type, "role": member.memberType, "owner": member.owner}
    ]
    groups = gg
}


# This functions verifies if the User has a role
# Params:
#   user_id
#   user_role
# Returns:
#   bool: True if the user has the user_role, otherwise False
user_has_role(user_role) {
    jwt = get_jwt_payload(dinput.jwt)
    orgs = user_get_orgs(jwt.user_id)
    roles = orgs[_].role
    user_role == roles
}

# check if the user has one of the provided roles in the organization
user_has_role_on_organization(roles, organization_id) {
    jwt := get_jwt_payload(dinput.jwt)
    some organization in user_get_orgs(jwt.user_id)
    to_number(organization_id) == to_number(organization.id)
    organization.role == roles[_]
}

# check if the user has one of the provided roles in the organization
user_is_assigned_to_training_program(user_id, training_program_id) {
    runtime = opa.runtime()
    search = urlquery.encode_object({"userId": format_int(user_id, 10), "trainingProgramId": training_program_id})
    value = http.send({
        "method": "GET",
        "url": concat("", [runtime.env.ENROLLMENTS_API_URL, "/v4/enrollments?", search]),
        "headers": {"x-api-key": runtime.env.ENROLLMENTS_API_KEY, "Content-type": "application/json"},
    })

    value.status_code == 200
    trace(sprintf("TEST123456 : %v", [value.body.count]))
    value.body.count > 0
}

# transforming an envoy input to darwin
# needs to be better implemeted with all of the options
envoyinput = c {
    c := {
        "headers": input.attributes.request.http.headers,
        "path": [j |
            j = split(input.attributes.request.http.path, "/")[_]
            j != ""
        ],
        "method": input.attributes.request.http.method,
        "query": input.attributes.parsed_query,
        "body": input.attributes.request.http.body
    }
}

has_key(x, k) {
    _ = x[k]
}

default dinput := {"method":"none"}

#####  own darwin input formatting
#envoy opa with a jwt
dinput = newinput {
    jwt := split(input.attributes.request.http.headers.authorization, " ")[1]
    jwt != ""
    parsedJwt := get_jwt_payload(jwt)
    userId := parsedJwt.user_id
    cache := user_authorization_cache(userId)
    newinput = object.union(envoyinput, {"jwt": jwt, "parsedJwt": parsedJwt, "userId": userId, "hasApiKey": false, "authorizationCache": cache})
}

#envoy opa api key without jwt
dinput = newinput {
    not input.attributes.request.http.headers.authorization
    hasApiKey := has_key(input.attributes.request.http.headers,"x-api-key")
    userId := input.attributes.request.http.headers["x-user-id"]
    cache := user_authorization_cache(userId)
    newinput = object.union(envoyinput, {"jwt": "", "parsedJwt": "", "userId": userId, "hasApiKey": hasApiKey, "authorizationCache": cache})
}

#envoy opa without jwt or api key
dinput = newinput {
    not input.attributes.request.http.headers.authorization
    not has_key(input.attributes.request.http.headers, "x-api-key")
    newinput = object.union(envoyinput, {"jwt": "", "parsedJwt": "", "userId": 0, "hasApiKey": false, "authorizationCache": ""})
}

#input not from envoy, regular input with jwt for darwin policies
dinput = newinput {
    input.jwt != ""
    not input.attributes.request
    trace("...dinput + jwt")
    parsedJwt := get_jwt_payload(input.jwt)
    trace(sprintf("...jwt exp={%v}",[parsedJwt.exp]))
    userId := parsedJwt.user_id
    trace(sprintf("...userId={%v}",[userId]))
    cache := user_authorization_cache(userId)
    newinput = object.union(input, {"parsedJwt": parsedJwt, "userId": userId, "hasApiKey": false, "authorizationCache": cache, "query": json.unmarshal(input.query), "body": json.unmarshal(input.body)})
}

#input not from envoy, regular input with api key for darwin policies
dinput = newinput {
    input.jwt == ""
    not input.attributes.request
    trace("...dinput + no jwt")
    headers := json.unmarshal(input.headers)
    hasApiKey := has_key(headers,"x-api-key")
    trace("...apikey found")
    userId := to_number(headers["x-user-id"])
    trace(sprintf("...userId={%v}",[userId]))
    cache := user_authorization_cache(userId)
    newinput = object.union(input, {"parsedJwt": "a", "userId": userId, "hasApiKey": true, "authorizationCache": cache, "query": json.unmarshal(input.query), "body": json.unmarshal(input.body), "headers": headers})
}