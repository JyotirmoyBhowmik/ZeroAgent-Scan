variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (staging, production)"
  default     = "production"
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block"
  default     = "10.100.0.0/16"
}

variable "db_instance_class" {
  type        = string
  description = "PostgreSQL RDS instance class"
  default     = "db.r6g.xlarge"
}

variable "db_master_password" {
  type        = string
  description = "PostgreSQL RDS master password (passed via AWS Secrets Manager or CI secret)"
  sensitive   = true
}
