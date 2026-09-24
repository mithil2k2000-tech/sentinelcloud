output "payment_service_role_arn" {
  value = aws_iam_role.payment_service.arn
}

output "account_service_role_arn" {
  value = aws_iam_role.account_service.arn
}
