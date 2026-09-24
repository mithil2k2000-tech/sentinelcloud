terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.15"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.33"
    }
  }

  # backend "s3" {} — a private, versioned, encrypted S3 bucket with a
  # DynamoDB lock table, not configured here since this scaffold doesn't
  # assume an account exists yet.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

# helm/kubernetes providers target module.eks's cluster for the Phase 4
# service mesh install (modules/mesh). EKS has no static client
# certificate — auth goes through a short-lived exec-generated token via
# the standard aws_eks_cluster_auth data source.
data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_ca_certificate)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_ca_certificate)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}
