# Network module — same four-trust-boundary layout as Azure/GCP:
#   subnet-gateway — ALB/ingress, internet-facing
#   subnet-eks     — EKS worker nodes
#   subnet-data    — VPC-endpoint-only access to Secrets Manager/S3/KMS
#   subnet-mgmt    — bastion / admin access

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "vpc-${var.project_name}-${var.environment}" })
}

locals {
  az   = data.aws_availability_zones.available.names[0]
  az_b = data.aws_availability_zones.available.names[1]

  subnets = {
    gateway = { cidr = "10.40.0.0/22", az = local.az }
    eks     = { cidr = "10.40.4.0/22", az = local.az }
    data    = { cidr = "10.40.8.0/22", az = local.az_b }
    mgmt    = { cidr = "10.40.12.0/22", az = local.az_b }
  }
}

resource "aws_subnet" "this" {
  for_each          = local.subnets
  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az
  tags              = merge(var.tags, { Name = "subnet-${each.key}-${var.environment}" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "igw-${var.project_name}-${var.environment}" })
}

resource "aws_route_table" "gateway" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = merge(var.tags, { Name = "rt-gateway-${var.environment}" })
}

resource "aws_route_table_association" "gateway" {
  subnet_id      = aws_subnet.this["gateway"].id
  route_table_id = aws_route_table.gateway.id
}

# eks/data/mgmt subnets deliberately have NO route to the internet gateway
# — they're private by default. Outbound-only internet access (for image
# pulls, etc.) would go through a NAT gateway added later, not a default
# route to the IGW.

# --- Security groups: deny-by-default, explicit allow only ---------------

resource "aws_security_group" "gateway" {
  name_prefix = "sg-${var.project_name}-gateway-"
  vpc_id      = aws_vpc.this.id
  tags        = var.tags

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "eks" {
  name_prefix = "sg-${var.project_name}-eks-"
  vpc_id      = aws_vpc.this.id
  tags        = var.tags

  ingress {
    description     = "HTTPS from the gateway security group only"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    security_groups  = [aws_security_group.gateway.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "data" {
  name_prefix = "sg-${var.project_name}-data-"
  vpc_id      = aws_vpc.this.id
  tags        = var.tags

  # Same control as Azure's data-subnet NSG / GCP's data-subnet firewall:
  # only the EKS security group may reach this tier.
  ingress {
    description     = "HTTPS from EKS workloads only"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    security_groups  = [aws_security_group.eks.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "mgmt" {
  name_prefix = "sg-${var.project_name}-mgmt-"
  vpc_id      = aws_vpc.this.id
  tags        = var.tags

  dynamic "ingress" {
    for_each = length(var.allowed_admin_cidrs) > 0 ? [1] : []
    content {
      description = "SSH from admin CIDRs only"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_admin_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
