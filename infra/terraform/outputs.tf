output "rds_endpoint" {
  description = "PostgreSQL RDS connection endpoint"
  value       = aws_db_instance.postgres.endpoint
}

output "kms_key_arn" {
  description = "KMS Master Key ARN for Credential Vault"
  value       = aws_kms_key.vault_master_key.arn
}

output "vpc_id" {
  description = "Main VPC ID"
  value       = aws_vpc.main.id
}
