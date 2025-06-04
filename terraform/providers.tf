# initiate required Providers
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.20.0"
    }
    azurerm = {
      source = "hashicorp/azurerm"
      version = "~> 3.90.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0" # or latest stable
  }
 }
}

provider "aws" {
  region     = var.aws_region
  alias      = "eu-central-1"
}

data "aws_availability_zones" "available" {}
