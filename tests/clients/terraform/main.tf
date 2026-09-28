# Terraform's S3 state backend against TeiFS, with S3-native locking (conditional
# writes: If-None-Match on the lock file). The backend's settings come from
# terraform.sh (-backend-config).
terraform {
  backend "s3" {
    key                         = "client-matrix/terraform.tfstate"
    region                      = "us-east-1"
    use_path_style              = true
    use_lockfile                = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
  }
}

variable "generation" {
  type = number
}

resource "terraform_data" "example" {
  input = var.generation
}

output "generation" {
  value = terraform_data.example.output
}
