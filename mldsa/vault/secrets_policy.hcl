
path "auth/approle/role/observatory/secret-id" {
  capabilities = ["read", "create", "update", "list"]
}

path "transit/keys/my-sign-key" {
  capabilities = ["read"]
}

path "transit/export/public-key/my-sign-key" {
  capabilities = ["read"]
}

path "transit/sign/my-sign-key" {
  capabilities = ["create", "update"]
}

path "transit/verify/my-sign-key" {
  capabilities = ["create", "update"]
}