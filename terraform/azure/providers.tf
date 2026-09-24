terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.53"
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

  # Remote state should be a private, encrypted, versioned backend (e.g. an
  # Azure Storage account with public access disabled, RBAC-only auth, and
  # a lock via native Terraform state locking). Left unconfigured here so
  # this scaffold doesn't assume any pre-existing subscription.
  # backend "azurerm" {}
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }
}

provider "azuread" {}

# helm/kubernetes providers target module.aks's cluster for the Phase 4
# service mesh install (modules/mesh). local_account_disabled = true on
# the cluster (modules/aks) means there's no static client certificate to
# authenticate with — kube_config's client_certificate/client_key come
# back empty on an AAD-RBAC-only cluster, so auth goes through `kubelogin`
# via the `exec` plugin instead, the standard pattern for this cluster
# configuration. "6dae42f8-4368-4678-94ff-3960e28e3630" is AKS's own
# well-known AAD server application ID, not a project-specific secret.
provider "kubernetes" {
  host                   = module.aks.host
  cluster_ca_certificate = base64decode(module.aks.cluster_ca_certificate)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "kubelogin"
    args        = ["get-token", "--login", "azurecli", "--server-id", "6dae42f8-4368-4678-94ff-3960e28e3630"]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.aks.host
    cluster_ca_certificate = base64decode(module.aks.cluster_ca_certificate)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "kubelogin"
      args        = ["get-token", "--login", "azurecli", "--server-id", "6dae42f8-4368-4678-94ff-3960e28e3630"]
    }
  }
}
