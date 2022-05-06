---
title: padlock v0.2.0
language_tabs:
  - shell: Shell
  - http: HTTP
  - javascript: JavaScript
  - ruby: Ruby
  - python: Python
  - php: PHP
  - java: Java
  - go: Go
toc_footers: []
includes: []
search: false
code_clipboard: true
highlight_theme: darkula
headingLevel: 2
generator: widdershins v4.0.1

---

<h1 id="padlock">padlock v0.2.0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

External AuthN / AuthZ support service for REST API RBAC

Base URLs:

* <a href="http://localhost:3000">http://localhost:3000</a>

<h1 id="padlock-management">Management</h1>

## User Management API liveness check

`GET /v1/alive`

Will return success to indicate user management REST API module is live

<h3 id="user-management-api-liveness-check-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="user-management-api-liveness-check-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## User Management API readiness check

`GET /v1/ready`

Will return success if user management REST API module is ready for use

<h3 id="user-management-api-readiness-check-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="user-management-api-readiness-check-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## List All Roles

`GET /v1/role`

List all roles the system is operating against

<h3 id="list-all-roles-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "roles": {
    "property1": {
      "permissions": [
        "string"
      ]
    },
    "property2": {
      "permissions": [
        "string"
      ]
    }
  },
  "success": true
}
```

<h3 id="list-all-roles-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[apis.RespListAllRoles](#schemaapis.resplistallroles)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## Get info on role

`GET /v1/role/{roleName}`

Query for information regarding one role, along with users assigned this role.

<h3 id="get-info-on-role-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|roleName|path|string|true|Role name|

> Example responses

> 200 Response

```json
{
  "assigned_users": [
    {
      "created_at": "string",
      "email": "string",
      "first_name": "string",
      "last_name": "string",
      "updated_at": "string",
      "user_id": "string",
      "username": "string"
    }
  ],
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "role": {
    "permissions": [
      "string"
    ]
  },
  "success": true
}
```

<h3 id="get-info-on-role-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[apis.RespRoleInfo](#schemaapis.resproleinfo)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## List all users

`GET /v1/user`

List all users currently managed by the system

<h3 id="list-all-users-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true,
  "users": [
    {
      "created_at": "string",
      "email": "string",
      "first_name": "string",
      "last_name": "string",
      "updated_at": "string",
      "user_id": "string",
      "username": "string"
    }
  ]
}
```

<h3 id="list-all-users-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[apis.RespListAllUsers](#schemaapis.resplistallusers)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## Define new user

`POST /v1/user`

Define a new user, and optionally assign roles to it

> Body parameter

```json
{
  "roles": [
    "string"
  ],
  "user": {
    "email": "string",
    "first_name": "string",
    "last_name": "string",
    "user_id": "string",
    "username": "string"
  }
}
```

<h3 id="define-new-user-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|body|body|[apis.ReqNewUserParams](#schemaapis.reqnewuserparams)|true|New user information|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="define-new-user-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## Delete user

`DELETE /v1/user/{userID}`

Remove user from the system.

<h3 id="delete-user-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|userID|path|string|true|User ID|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="delete-user-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## Get info on user

`GET /v1/user/{userID}`

Query for information regarding one user.

<h3 id="get-info-on-user-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|userID|path|string|true|User ID|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true,
  "user": {
    "associatedPermission": [
      "string"
    ],
    "created_at": "string",
    "email": "string",
    "first_name": "string",
    "last_name": "string",
    "roles": [
      "string"
    ],
    "updated_at": "string",
    "user_id": "string",
    "username": "string"
  }
}
```

<h3 id="get-info-on-user-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[apis.RespUserInfo](#schemaapis.respuserinfo)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## Update a user's info

`PUT /v1/user/{userID}`

Update an existing user's information

> Body parameter

```json
{
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "user_id": "string",
  "username": "string"
}
```

<h3 id="update-a-user's-info-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|userID|path|string|true|User ID|
|body|body|[models.UserConfig](#schemamodels.userconfig)|true|Updated user information|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="update-a-user's-info-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

## Update a user's roles

`PUT /v1/user/{userID}/roles`

Change the user's roles to what caller requested

> Body parameter

```json
{
  "roles": [
    "string"
  ]
}
```

<h3 id="update-a-user's-roles-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|userID|path|string|true|User ID|
|body|body|[apis.ReqNewUserRoles](#schemaapis.reqnewuserroles)|true|User's new roles|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="update-a-user's-roles-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="padlock-authorize">Authorize</h1>

## Check whether a REST API call is allowed

`GET /v1/allow`

Check whether a REST API call is allowed. The parameters of the call is passed in

<h3 id="check-whether-a-rest-api-call-is-allowed-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|X-Forwarded-Host|header|string|true|Host of the API call to authorize|
|X-Forwarded-Uri|header|string|true|URI path of the API call to authorize|
|X-Forwarded-Method|header|string|true|HTTP method of the API call to authorize|
|X-Caller-UserID|header|string|true|ID of the user making the API call to authorize|
|X-Caller-Username|header|string|false|Username of the user making the API call to authorize|
|X-Caller-Firstname|header|string|false|First name / given name of the user making the API call to authorize|
|X-Caller-Lastname|header|string|false|Last name / surname / family name of the user making the API call to authorize|
|X-Caller-Email|header|string|false|Email of the user making the API call to authorize|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="check-whether-a-rest-api-call-is-allowed-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="padlock-authenticate">Authenticate</h1>

## Authenticate a user

`GET /v1/authenticate`

Authticate a user by verifiying the bearer token provided

<h3 id="authenticate-a-user-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|Padlock-Request-ID|header|string|false|User provided request ID to match against logs|
|Authorization|header|string|true|User must provide a bearer token|

> Example responses

> 200 Response

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}
```

<h3 id="authenticate-a-user-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|success|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|error|string|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|error|string|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|error|string|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|error|[goutils.RestAPIBaseResponse](#schemagoutils.restapibaseresponse)|

<aside class="success">
This operation does not require authentication
</aside>

# Schemas

<h2 id="tocS_apis.ReqNewUserParams">apis.ReqNewUserParams</h2>

<a id="schemaapis.reqnewuserparams"></a>
<a id="schema_apis.ReqNewUserParams"></a>
<a id="tocSapis.reqnewuserparams"></a>
<a id="tocsapis.reqnewuserparams"></a>

```json
{
  "roles": [
    "string"
  ],
  "user": {
    "email": "string",
    "first_name": "string",
    "last_name": "string",
    "user_id": "string",
    "username": "string"
  }
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|roles|[string]|false|none|Roles list the roles to assign to this user|
|user|[models.UserConfig](#schemamodels.userconfig)|true|none|User contains the new user parameters|

<h2 id="tocS_apis.ReqNewUserRoles">apis.ReqNewUserRoles</h2>

<a id="schemaapis.reqnewuserroles"></a>
<a id="schema_apis.ReqNewUserRoles"></a>
<a id="tocSapis.reqnewuserroles"></a>
<a id="tocsapis.reqnewuserroles"></a>

```json
{
  "roles": [
    "string"
  ]
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|roles|[string]|false|none|Roles list the roles to assign to this user|

<h2 id="tocS_apis.RespListAllRoles">apis.RespListAllRoles</h2>

<a id="schemaapis.resplistallroles"></a>
<a id="schema_apis.RespListAllRoles"></a>
<a id="tocSapis.resplistallroles"></a>
<a id="tocsapis.resplistallroles"></a>

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "roles": {
    "property1": {
      "permissions": [
        "string"
      ]
    },
    "property2": {
      "permissions": [
        "string"
      ]
    }
  },
  "success": true
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|error|[goutils.ErrorDetail](#schemagoutils.errordetail)|false|none|Error are details in case of errors|
|request_id|string|true|none|RequestID gives the request ID to match against logs|
|roles|object|true|none|Roles are the roles|
|» **additionalProperties**|[common.UserRoleConfig](#schemacommon.userroleconfig)|false|none|none|
|success|boolean|true|none|Success indicates whether the request was successful|

<h2 id="tocS_apis.RespListAllUsers">apis.RespListAllUsers</h2>

<a id="schemaapis.resplistallusers"></a>
<a id="schema_apis.RespListAllUsers"></a>
<a id="tocSapis.resplistallusers"></a>
<a id="tocsapis.resplistallusers"></a>

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true,
  "users": [
    {
      "created_at": "string",
      "email": "string",
      "first_name": "string",
      "last_name": "string",
      "updated_at": "string",
      "user_id": "string",
      "username": "string"
    }
  ]
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|error|[goutils.ErrorDetail](#schemagoutils.errordetail)|false|none|Error are details in case of errors|
|request_id|string|true|none|RequestID gives the request ID to match against logs|
|success|boolean|true|none|Success indicates whether the request was successful|
|users|[[models.UserInfo](#schemamodels.userinfo)]|true|none|Users are the users in system|

<h2 id="tocS_apis.RespRoleInfo">apis.RespRoleInfo</h2>

<a id="schemaapis.resproleinfo"></a>
<a id="schema_apis.RespRoleInfo"></a>
<a id="tocSapis.resproleinfo"></a>
<a id="tocsapis.resproleinfo"></a>

```json
{
  "assigned_users": [
    {
      "created_at": "string",
      "email": "string",
      "first_name": "string",
      "last_name": "string",
      "updated_at": "string",
      "user_id": "string",
      "username": "string"
    }
  ],
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "role": {
    "permissions": [
      "string"
    ]
  },
  "success": true
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|assigned_users|[[models.UserInfo](#schemamodels.userinfo)]|false|none|AssignedUsers is the list of users being assigned this role|
|error|[goutils.ErrorDetail](#schemagoutils.errordetail)|false|none|Error are details in case of errors|
|request_id|string|true|none|RequestID gives the request ID to match against logs|
|role|[common.UserRoleConfig](#schemacommon.userroleconfig)|true|none|Role is info on this role|
|success|boolean|true|none|Success indicates whether the request was successful|

<h2 id="tocS_apis.RespUserInfo">apis.RespUserInfo</h2>

<a id="schemaapis.respuserinfo"></a>
<a id="schema_apis.RespUserInfo"></a>
<a id="tocSapis.respuserinfo"></a>
<a id="tocsapis.respuserinfo"></a>

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true,
  "user": {
    "associatedPermission": [
      "string"
    ],
    "created_at": "string",
    "email": "string",
    "first_name": "string",
    "last_name": "string",
    "roles": [
      "string"
    ],
    "updated_at": "string",
    "user_id": "string",
    "username": "string"
  }
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|error|[goutils.ErrorDetail](#schemagoutils.errordetail)|false|none|Error are details in case of errors|
|request_id|string|true|none|RequestID gives the request ID to match against logs|
|success|boolean|true|none|Success indicates whether the request was successful|
|user|[users.UserDetailsWithPermission](#schemausers.userdetailswithpermission)|true|none|User is info on this user|

<h2 id="tocS_common.UserRoleConfig">common.UserRoleConfig</h2>

<a id="schemacommon.userroleconfig"></a>
<a id="schema_common.UserRoleConfig"></a>
<a id="tocScommon.userroleconfig"></a>
<a id="tocscommon.userroleconfig"></a>

```json
{
  "permissions": [
    "string"
  ]
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|permissions|[string]|true|none|AssignedPermissions is the list of permissions assigned to a role|

<h2 id="tocS_goutils.ErrorDetail">goutils.ErrorDetail</h2>

<a id="schemagoutils.errordetail"></a>
<a id="schema_goutils.ErrorDetail"></a>
<a id="tocSgoutils.errordetail"></a>
<a id="tocsgoutils.errordetail"></a>

```json
{
  "code": 0,
  "detail": "string",
  "message": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|code|integer|true|none|Code is the response code|
|detail|string|false|none|Detail is an optional descriptive message providing additional details on the error|
|message|string|false|none|Msg is an optional descriptive message|

<h2 id="tocS_goutils.RestAPIBaseResponse">goutils.RestAPIBaseResponse</h2>

<a id="schemagoutils.restapibaseresponse"></a>
<a id="schema_goutils.RestAPIBaseResponse"></a>
<a id="tocSgoutils.restapibaseresponse"></a>
<a id="tocsgoutils.restapibaseresponse"></a>

```json
{
  "error": {
    "code": 0,
    "detail": "string",
    "message": "string"
  },
  "request_id": "string",
  "success": true
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|error|[goutils.ErrorDetail](#schemagoutils.errordetail)|false|none|Error are details in case of errors|
|request_id|string|true|none|RequestID gives the request ID to match against logs|
|success|boolean|true|none|Success indicates whether the request was successful|

<h2 id="tocS_models.UserConfig">models.UserConfig</h2>

<a id="schemamodels.userconfig"></a>
<a id="schema_models.UserConfig"></a>
<a id="tocSmodels.userconfig"></a>
<a id="tocsmodels.userconfig"></a>

```json
{
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "user_id": "string",
  "username": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|email|string|false|none|Email is the user's email|
|first_name|string|false|none|FirstName is the user's first name / given name|
|last_name|string|false|none|LastName is the user's last name / surname / family name|
|user_id|string|true|none|UserID is the user's ID|
|username|string|false|none|UserName is the username|

<h2 id="tocS_models.UserInfo">models.UserInfo</h2>

<a id="schemamodels.userinfo"></a>
<a id="schema_models.UserInfo"></a>
<a id="tocSmodels.userinfo"></a>
<a id="tocsmodels.userinfo"></a>

```json
{
  "created_at": "string",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "updated_at": "string",
  "user_id": "string",
  "username": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|created_at|string|false|none|CreatedAt is when the user entry is created|
|email|string|false|none|Email is the user's email|
|first_name|string|false|none|FirstName is the user's first name / given name|
|last_name|string|false|none|LastName is the user's last name / surname / family name|
|updated_at|string|false|none|UpdatedAt is when the user entry was last updated|
|user_id|string|true|none|UserID is the user's ID|
|username|string|false|none|UserName is the username|

<h2 id="tocS_users.UserDetailsWithPermission">users.UserDetailsWithPermission</h2>

<a id="schemausers.userdetailswithpermission"></a>
<a id="schema_users.UserDetailsWithPermission"></a>
<a id="tocSusers.userdetailswithpermission"></a>
<a id="tocsusers.userdetailswithpermission"></a>

```json
{
  "associatedPermission": [
    "string"
  ],
  "created_at": "string",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "roles": [
    "string"
  ],
  "updated_at": "string",
  "user_id": "string",
  "username": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|associatedPermission|[string]|false|none|AssociatedPermission list of permissions the user has based on the roles associated with<br />the user|
|created_at|string|false|none|CreatedAt is when the user entry is created|
|email|string|false|none|Email is the user's email|
|first_name|string|false|none|FirstName is the user's first name / given name|
|last_name|string|false|none|LastName is the user's last name / surname / family name|
|roles|[string]|false|none|Roles are the roles associated with the user|
|updated_at|string|false|none|UpdatedAt is when the user entry was last updated|
|user_id|string|true|none|UserID is the user's ID|
|username|string|false|none|UserName is the username|
