config {
  role {
    name            = "custom-role"
    transformations = ["custom-fpe"]
  }

  fpe {
    name          = "custom-fpe"
    template      = "custom-template"
    tweak_source  = "supplied"
    allowed_roles = ["custom-role"]
  }

  input {
    value          = "1234-5678-9012-3456"
    transformation = "custom-fpe"
    tweak          = "H0mSPAfSJg=="
  }
}