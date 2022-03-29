# Padlock - External Authorization Service For REST APIs

`Padlock` is a simple, configurable, and flexible authentication (AuthN) and authorization (AuthZ) service for REST APIs.

The AuthN / AuthZ API supports

* [Nginx Subrequest Authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)

* [Traefik ForwardAuth Middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)

* etc.

as an external auth server responding to validation requests from the request proxy.

---

## [Table of Content](#table-of-content)

- [1. Overview](#1-overview)
  * [1.1 User Management](#11-user-management)
  * [1.2 Authentication](#12-authentication)
  * [1.3 Authorization](#13-authorization)
- [2. Configuration](#2-configuration)
  * [2.1 User Roles](#21-user-roles)
  * [2.2 Authorization Rules](#22-authorization-rules)
  * [2.3 Runtime User Discovery](#23-runtime-user-discovery)

---

# [1. Overview](#table-of-content)

<p align="center">
  <img src="docs/highlevel.png">
</p>

`Padlock` consists of three submodules:

* `User Management`

* `Authentication`

* `Authorization`

## [1.1 User Management](#table-of-content)

The user management submodule is the administrative API of `Padlock`. Through this API, an administrator can

* Perform CRUD operations on users known and managed by `Padlock`.
* Associate users with user roles.

> **NOTES:** A user role defines what system permissions a user of this role have within the system being protected. In the context of REST API RBAC, these permissions mainly govern which API calls a user is allowed to make against the REST APIs. **By associating roles with a user, that user inherits the permissions associated with those user roles.**

The set of user roles `Padlock` operates with is provided via configuration at program start; whereas users are administrator defined, or can be [learned at runtime](#23-runtime-user-discovery). The mapping between users and user roles provides the basis for [user request authorization](#13-authorization)

> **NOTES:** A user without permissions will never pass authorization.

## [1.2 Authentication](#table-of-content)

The authentication submodule performs user authentication for user requests arriving at the request proxy. Specifically, the submodule processes the bearer token found in the authorization header included with the user request, and validates that token.

```http
GET /v1/authenticate HTTP/1.1
...
Authorization: bearer {{ token }}
...
```

`Padlock` is designed to validate Oauth2 / OpenID JWT tokens; so the authentication submodule will validate the signature of the bearer token against the Public key of the Oauth2 / OpenID provider's signing key pair.

> **NOTES:** Token introspection will be implemented in the future.

Upon successful validation, the submodule will respond to the request proxy with the following additional information regarding the user as response headers:

* User ID
* Username
* First name
* Last name
* Email

These additional parameters are parsed from the various claims within the JWT bearer token.

> **NOTE:** Since different Oauth2 / OpenID providers include different claims in their JWT, the user is responsible for providing via [configuration](ref/general_application_config.md#authentication-submodule-configuration) which claims to parse for the additional user metadata.

> **NOTE:** Aside from `User ID`, the other metadata fields are optional depending on the presence of the associated claims within the JWT token. **The JWT token must provide `User ID` as a claim.**

## [1.3 Authorization](#table-of-content)

The authorization submodule performs authorization for user requests arriving at the request proxy (i.e. is a user allowed to make that request?). The submodule fetches the parameters regarding the user request from the headers of the HTTP call from the request proxy to `Padlock` for authorization.

```http
GET /v1/allow HTTP/1.1
...
X-Forwarded-Host: {{ User request "host" }}
X-Forwarded-Uri: {{ User request URI path }}
X-Forwarded-Method: {{ User request HTTP method }}
X-Caller-UserID: {{ Caller user ID }}
X-Caller-Username: {{ Caller username }}
X-Caller-Firstname: {{ Caller first name }}
X-Caller-Lastname: {{ Caller last name }}
X-Caller-Email: {{ Caller email }}
...
```

The authorization submodule operates against

* Pre-defined [authorization rules](#22-authorization-rules)
* Mapping between [users and roles](#11-user-management)

Authorization rules define what system permissions would allow a user to make a specific request, and the mapping between users and user roles define what system permissions a user has.

The submodule uses the following request parameters

* `X-Forwarded-Host`
* `X-Forwarded-Uri`
* `X-Forwarded-Method`

to match the request against a specific authorization rule.

With the authorization rule, this user is authorized based on whether the user's system permissions passes the permission check of that authorization rule.

For an unknown user, if [runtime user discovery](#table-of-content) is enabled, the authorization submodule will define a new user within the database using the request parameters

* `X-Caller-UserID`
* `X-Caller-Username`
* `X-Caller-Firstname`
* `X-Caller-Lastname`
* `X-Caller-Email`

> **NOTES:** The newly created user entry starts with no user roles.

# [2. Configuration](#table-of-content)

## [2.1 User Roles](#table-of-content)

## [2.2 Authorization Rules](#table-of-content)

## [2.3 Runtime User Discovery](#table-of-content)
