variable "project_id" {
  type = string
}

variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "region" {
  type = string
}

variable "allowed_admin_cidrs" {
  type    = list(string)
  default = []
}
