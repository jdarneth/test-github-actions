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

is_valid_path {
  regex.match("^xxx/.*$", input.spec.data[_].remoteRef.key)
}

deny[msg] {
  input.kind == "ExternalSecret" AND not is_valid_path
  msg := "the path is not allowed..."
}
