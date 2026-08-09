# EndpointGuard Production Infrastructure Stub (AWS/Azure/GCP)
# Defines VPC, PostgreSQL 15 RDS Multi-AZ, EKS/ECS cluster, and KMS Master Key for Vault envelope encryption.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "endpointguard-terraform-state-prod"
    key            = "prod/endpointguard.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "endpointguard-tf-lock"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "EndpointGuard"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Security    = "OWASP-ASVS-Level-2"
    }
  }
}

# ---------------------------------------------------------------------------
# 1. KMS Master Key for EndpointGuard Credential Vault
# ---------------------------------------------------------------------------
resource "aws_kms_key" "vault_master_key" {
  description             = "KMS Key for EndpointGuard AES-256-GCM Envelope Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "vault_master_key_alias" {
  name          = "alias/endpointguard-vault-${var.environment}"
  target_key_id = aws_kms_key.vault_master_key.key_id
}

# ---------------------------------------------------------------------------
# 2. VPC & Isolated Subnets
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "endpointguard-vpc-${var.environment}"
  }
}

# ---------------------------------------------------------------------------
# 3. PostgreSQL 15+ RDS Cluster (Encrypted at Rest with KMS)
# ---------------------------------------------------------------------------
resource "aws_db_instance" "postgres" {
  identifier                  = "endpointguard-pg-${var.environment}"
  engine                      = "postgres"
  engine_version              = "15.6"
  instance_class              = var.db_instance_class
  allocated_storage           = 100
  max_allocated_storage       = 500
  storage_type                = "gp3"
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.vault_master_key.arn
  multi_az                    = true
  publicly_accessible         = false
  auto_minor_version_upgrade  = true
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "endpointguard-pg-final-snapshot"

  db_name  = "endpointguard"
  username = "endpointguard_admin"
  password = var.db_master_password

  parameters = [
    {
      name  = "rds.force_ssl"
      value = "1"
    }
  ]
}
