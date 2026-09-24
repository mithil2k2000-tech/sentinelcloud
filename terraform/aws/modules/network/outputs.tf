output "vpc_id" {
  value = aws_vpc.this.id
}

output "subnet_ids" {
  value = { for k, s in aws_subnet.this : k => s.id }
}

output "subnet_cidrs" {
  value = { for k, v in local.subnets : k => v.cidr }
}

output "security_group_ids" {
  value = {
    gateway = aws_security_group.gateway.id
    eks     = aws_security_group.eks.id
    data    = aws_security_group.data.id
    mgmt    = aws_security_group.mgmt.id
  }
}
