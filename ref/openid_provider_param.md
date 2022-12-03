# OpenID Provider Connection Parameters

See below for an example of the OpenID provider connection parameter file for Padlock.

```json
{
  "issuer": "{{ You OpenID Issuer URL }}",
  "client_id": "{{ OAuth2 client credentials }}",
  "client_cred": "{{ OAuth2 client credentials }}",
  "http_tlc_ca": "{{ Custom CA file if your issuer uses one }}"
}
```

| Field | Required | Description | Note |
|-------|----------|-------------|------|
| `issuer` | YES | The OpenID issuer URL | The application will fetch the OpenID provider configuration from `/.well-known/openid-configuration` relative to this URL. |
| `client_id` | NO | The OAuth2 client ID to operate as | Only required if performing introspection. |
| `client_cred` | NO | The OAuth2 client credentials | Only required if performing introspection. |
| `http_tlc_ca` | NO | Path to a certificate authority PEM to use for the HTTPS connection | Only needed if this OpenID provider uses a custom / private trust chain that is not recorded in the system trust store. |
