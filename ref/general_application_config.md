# Padlock Application Configuration

See below for an example of the complete Padlock application configuration file. Detailed explanation for each field are in the comments.

> **NOTES:** Configuration file is to be provided as a single YAML file. However, it is separated into separate sections here for presentation reasons.

---

## Custom Validation REGEX patterns

The patterns given here provide validation for the corresponding user input types.

```yaml
customValidationRegex:
  # User ID input validation
  userID: ^([[:alnum:]]|-|_)+$
  # Username input validation
  username: ^([[:alnum:]]|-|_)+$
  # User permission name input validation
  permission: ^([[:alnum:]]|-|_|:|\.)+$
  # User personal name input validation
  personalName: ^([[:alnum:]]|-)+$
  # User role name input validation
  roleName: ^([[:alnum:]]|-|_)+$
```

---

## User Management Submodule Configuration

This is the administrative API for padlock. An administrator operates user CRUD, and role assignment through this submodule.

```yaml
userManagement:
  ####################################
  # REST API configuration
  #
  apis:
    # REST API end-point configuration
    endPoint:
      # Runtime prefix for API end-point path
      pathPrefix: /
    # REST API request logging configuration
    requestLogging:
      # When logging API requests, do not log these headers
      skipHeaders:
        - WWW-Authenticate
        - Authorization
        - Proxy-Authenticate
        - Proxy-Authorization
  ####################################
  # API HTTP service configuration
  #
  service:
    # HTTP service listening port
    appPort: 3000
    # HTTP service listening interface
    listenOn: 0.0.0.0
    # HTTP service timeout in seconds
    timeoutSecs:
      # Maximum amount of time to wait for the next request when keep-alive is enabled
      # in seconds. If idle timeout is zero, the value of read timeout is used. If both are
      # zero, there is no timeout.
      idle: 300
      # Maximum duration for reading the entire request, including the body in seconds.
      # A zero or negative value means there will be no timeout.
      read: 60
      # Maximum duration before timing out writes of the response in seconds. A zero or
      # negative value means there will be no timeout.
      write: 60
  ####################################
  # User roles used by the management submodule
  #
  # Roles defined here are the available roles for assigning to users. At the start of execution,
  # the management submodule will synchronize available roles defined here with user roles
  # maintained in the user database.
  #
  userRoles:
    # User roles are defined as a dictionary
    #
    # {{ User Role name }}:
    #    permissions:
    #      - {{ permission 1 }}
    #      - {{ permission 2 }}
    #      ...
    #      - {{ permission N }}
    #
    # The role name can be any valid YAML key. However, the system expects that the name are
    # valid (i.e. matches the REGEX pattern defined at customValidationRegex.roleName).
    #
    # The system also expects that the permission names are valid (i.e. match the REGEX pattern
    # defined at customValidationRegex.permission), and the permissions assigned to a role is
    # non-repeating.
    admin:
      permissions:
        - read
        - write
        - modify
        - delete
    reader:
      permissions:
        - read
    writer:
      permissions:
        - write
    user:
      permissions:
        - read
        - write
        - modify
```

---

## Authorization Submodule Configuration

The authorization submodule accepts verification requests from HTTP request proxies to determine whether a user is allowed to make a particular REST call. The parameters of the request to authorize must be presented via HTTP headers.

```yaml
authorize:
  ####################################
  # REST API configuration
  #
  apis:
    # REST API end-point configuration
    endPoint:
      # Runtime prefix for API end-point path
      pathPrefix: /
    # REST API request logging configuration
    requestLogging:
      # When logging API requests, do not log these headers
      skipHeaders:
        - WWW-Authenticate
        - Authorization
        - Proxy-Authenticate
        - Proxy-Authorization
  ####################################
  # API HTTP service configuration
  #
  service:
    # HTTP service listening port
    appPort: 3001
    # HTTP service listening interface
    listenOn: 0.0.0.0
    # HTTP service timeout in seconds
    timeoutSecs:
      # Maximum amount of time to wait for the next request when keep-alive is enabled
      # in seconds. If idle timeout is zero, the value of read timeout is used. If both are
      # zero, there is no timeout.
      idle: 300
      # Maximum duration for reading the entire request, including the body in seconds.
      # A zero or negative value means there will be no timeout.
      read: 60
      # Maximum duration before timing out writes of the response in seconds. A zero or
      # negative value means there will be no timeout.
      write: 60
  ####################################
  # Defines how the submodule should handle an unknown user ID
  #
  forUnknownUser:
    # Whether to automatically record the new user, with no roles assigned to the user.
    autoAdd: true
  ####################################
  # When a HTTP proxy sends a authorization request to padlock, which HTTP headers
  # should the submodule fetch request parameters from.
  #
  requestParamHeaders:
    # Host of the request to authorize
    host: X-Forwarded-Host
    # URI Path of the request to authorize
    path: X-Forwarded-Uri
    # HTTP method of the request to authorize
    method: X-Forwarded-Method
    # Caller user ID of the request to authorize
    userID: X-Caller-UserID
    # Caller username of the request to authorize
    username: X-Caller-Username
    # Caller first name of the request to authorize
    firstName: X-Caller-Firstname
    # Caller last name of the request to authorize
    lastName: X-Caller-Lastname
    # Caller email address of the request to authorize
    email: X-Caller-Email
  ####################################
  # REST request authorization rules
  #
  # The authorization submodules follows the rules defines here when determining whether a
  # REST request is allowed. The submodule checks the:
  #   * Host
  #   * URI Path
  #   * Method
  #
  # to determine which user permissions will allow that REST request to pass. A REST request
  # whose parameter do not match any defined rules are blocked.
  #
  # After determining the permissions list, that is compared against the permissions associated
  # with the user (based on its assigned roles) to see determine to allow the request.
  #
  rules:
    # Authorization rules are grouped by HTTP "host"
    - host: dev-00.testing.org
      # For each host, list out the URI path to check against.
      allowedPaths:
        # Each path is defined by a regex pattern describing it. This is expected to
        # be a PCRE2 complaint regex pattern.
        #
        # NOTE: a wildcard pattern would just be "^.*$"
        - pathPattern: "^/path1$"
          # For each URI path, list out the HTTP methods allow.
          allowedMethods:
            - method: GET
              # For a given HTTP method, which permissions will allow the REST request to pass.
              allowedPermissions:
                - read
            - method: POST
              allowedPermissions:
                - write
        # As multiple path regex patterns may start with the same prefix, the submodule checks
        # each regex pattern from longest to shortest (more specific to less specific).
        - pathPattern: "^/path1/([[:alnum:]]|-)+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - read
            - method: PUT
              allowedPermissions:
                - modify
            - method: DELETE
              allowedPermissions:
                - modify
        - pathPattern: "^/path2/[[:alpha:]]+/?$"
          allowedMethods:
            # If method is "*", this mean "any HTTP method" is allowed.
            - method: "*"
              allowedPermissions:
                - read
                - write
                - modify
                - delete
    # If host is "*", this mean "any HTTP host" will match.
    - host: "*"
      allowedPaths:
        - pathPattern: "^/path3/?$"
          allowedMethods:
            - method: "*"
              allowedPermissions:
                - read
                - write
                - modify
                - delete
        - pathPattern: "^/path3/([[:alnum:]]|-|_)+/?$"
          allowedMethods:
            - method: GET
              allowedPermissions:
                - read
            - method: PUT
              allowedPermissions:
                - modify
```

---

## Authentication Submodule Configuration

The authentication submodule accepts verification requests from HTTP request proxies to determine whether a user is authenticated. The submodule authenticates a user via OpenID token validation (the OpenID provider configuration is supplied through a separate file), where the token is presented as a bearer authorization token.

Upon successful token validation, the submodule will add these additional headers to the response. Always present are

  * User's user ID with the OpenID provider: store as `authorize.requestParamHeaders.userID`

If available

  * User's OpenID username: store as `authorize.requestParamHeaders.username`
  * User's first name: store as `authorize.requestParamHeaders.firstName`
  * User's last name: store as `authorize.requestParamHeaders.lastName`
  * User's email: store as `authorize.requestParamHeaders.email`

These values are extracted from the token claims, so the user will need to indicate which token claims provide which piece of information on the user.

> **NOTE:** The example given here are based on tokens generated by KeyCloak.

```yaml
authenticate:
  # Whether to enable the authentication submodule
  enabled: true
  ####################################
  # REST API configuration
  #
  apis:
    # REST API end-point configuration
    endPoint:
      # Runtime prefix for API end-point path
      pathPrefix: /
    # REST API request logging configuration
    requestLogging:
      # When logging API requests, do not log these headers
      skipHeaders:
        - WWW-Authenticate
        - Authorization
        - Proxy-Authenticate
        - Proxy-Authorization
  ####################################
  # API HTTP service configuration
  #
  service:
    # HTTP service listening port
    appPort: 3002
    # HTTP service listening interface
    listenOn: 0.0.0.0
    # HTTP service timeout in seconds
    timeoutSecs:
      # Maximum amount of time to wait for the next request when keep-alive is enabled
      # in seconds. If idle timeout is zero, the value of read timeout is used. If both are
      # zero, there is no timeout.
      idle: 300
      # Maximum duration for reading the entire request, including the body in seconds.
      # A zero or negative value means there will be no timeout.
      read: 60
      # Maximum duration before timing out writes of the response in seconds. A zero or
      # negative value means there will be no timeout.
      write: 60
  ####################################
  # User OpenID token claims of interest
  #
  targetClaims:
    # User ID claim
    userID: sub
    # Username claim
    username: preferred_username
    # Email claim
    email: email
    # First name claim
    firstName: given_name
    # Last name claim
    lastName: family_name
```

# Default Configuration

The binary comes with some preset default values.

```yaml
customValidationRegex:
  userID: "^([[:alnum:]]|-|_)+$"
  username: "^([[:alnum:]]|-|_)+$"
  personalName: "^([[:alnum:]]|-)+$"
  roleName: "^([[:alnum:]]|-|_)+$"
  permission: "^([[:alnum:]]|-|_|:)+$"

userManagement:
  apis:
    endPoint:
      pathPrefix: "/"
    requestLogging:
      skipHeaders:
        - "WWW-Authenticate"
        - "Authorization"
        - "Proxy-Authenticate"
        - "Proxy-Authorization"
  service:
    appPort: 3000
    listenOn: "0.0.0.0"
    timeoutSecs:
      idle: 600
      read: 60
      write: 60

authorize:
  apis:
    endPoint:
      pathPrefix: "/"
    requestLogging:
      skipHeaders:
        - "WWW-Authenticate"
        - "Authorization"
        - "Proxy-Authenticate"
        - "Proxy-Authorization"
  service:
    appPort: 3001
    listenOn: "0.0.0.0"
    timeoutSecs:
      idle: 600
      read: 60
      write: 60
  requestParamHeaders:
    host: "X-Forwarded-Host"
    path: "X-Forwarded-Uri"
    method: "X-Forwarded-Method"
    userID: "X-Caller-UserID"
    username: "X-Caller-Username"
    firstName: "X-Caller-Firstname"
    lastName: "X-Caller-Lastname"
    email: "X-Caller-Email"

authenticate:
  enabled: False
  apis:
    endPoint:
      pathPrefix: "/"
    requestLogging:
      skipHeaders:
        - "WWW-Authenticate"
        - "Authorization"
        - "Proxy-Authenticate"
        - "Proxy-Authorization"
  service:
    appPort: 3002
    listenOn: "0.0.0.0"
    timeoutSecs:
      idle: 600
      read: 60
      write: 60
  targetClaims:
    userID: sub
```

A user's configuration may skip these fields; the application will merge the provided configuration with the default values to form the final runtime configuration. **However, the user must provide the missing configuration.**
