provider "aws" {
  region     = var.aws_region
  access_key = var.Access_Key_AWS
  secret_key = var.Access_Secret_AWS
}

data "aws_availability_zones" "available" {}
