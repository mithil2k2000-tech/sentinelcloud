terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
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

  # backend "gcs" {} — a private, versioned, uniform-access GCS bucket,
  # not configured here since this scaffold doesn't assume a project exists.
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# helm/kubernetes providers target module.gke's cluster for the Phase 4
# service mesh install (modules/mesh). GKE has no static client
# certificate by default (Workload Identity + short-lived tokens) — auth
# goes through the caller's own gcloud/ADC credentials via
# google_client_config, the standard pattern for this setup.
data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${module.gke.cluster_endpoint}"
  cluster_ca_certificate = base64decode(module.gke.cluster_ca_certificate)
  token                  = data.google_client_config.default.access_token
}

provider "helm" {
  kubernetes {
    host                   = "https://${module.gke.cluster_endpoint}"
    cluster_ca_certificate = base64decode(module.gke.cluster_ca_certificate)
    token                  = data.google_client_config.default.access_token
  }
}
