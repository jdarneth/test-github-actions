# METADATA
# title: Wrong Secret Path not Allowed
# description: Not allowed secret path in configuration file.
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: ID001
#   severity: HIGH
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID001

is_external_secret {
  input.kind == "ExternalSecret"
}

is_valid_path {
  regex.match("^xxx/.*$", input.spec.data[_].remoteRef.key)
}

deny[msg] {
  is_external_secret 
  not is_valid_path
  msg := sprintf("the path %s is not allowed.", input.spec.data[_].remoteRef.key)
}
