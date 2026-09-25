# Network module — same four-trust-boundary layout as terraform/azure, so
# the two clouds map onto the same threat-model schema.
#
#   subnet-gateway — ingress only
#   subnet-gke     — GKE nodes running payment-service, account-service, etc.
#   subnet-data    — reserved for any future VM/Cloud SQL data tier +
#                    private Google access for Secret Manager/GCS/KMS
#   subnet-mgmt    — bastion / admin access
#
# Note on GCS/Secret Manager specifically: those are managed services, not
# VPC-attached instances, so firewall rules don't govern access to them —
# IAM does (see modules/iam's scoped custom role + modules/storage's
# bucket-level binding). The firewall rules below govern instance-to-
# instance traffic (GKE nodes and anything later added to subnet-data,
# e.g. Cloud SQL via a VM-based proxy); private_ip_google_access on every
# subnet is what lets instances reach the managed services without a
# public IP either way.

resource "google_compute_network" "this" {
  name                    = "vpc-${var.project_name}-${var.environment}"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

locals {
  subnets = {
    gateway = { cidr = "10.30.0.0/22" }
    gke     = { cidr = "10.30.4.0/22" }
    data    = { cidr = "10.30.8.0/22" }
    mgmt    = { cidr = "10.30.12.0/22" }
  }
}

resource "google_compute_subnetwork" "this" {
  for_each                 = local.subnets
  name                     = "subnet-${each.key}"
  ip_cidr_range            = each.value.cidr
  region                   = var.region
  network                  = google_compute_network.this.id
  private_ip_google_access = true

  dynamic "secondary_ip_range" {
    for_each = each.key == "gke" ? [1] : []
    content {
      range_name    = "pods"
      ip_cidr_range = "10.31.0.0/16"
    }
  }

  dynamic "secondary_ip_range" {
    for_each = each.key == "gke" ? [1] : []
    content {
      range_name    = "services"
      ip_cidr_range = "10.32.0.0/20"
    }
  }
}

# --- Firewall rules: deny-by-default, explicit allow only -----------------
# GCP firewall rules select which instances they apply to via target_tags
# (or target_service_accounts) — not via a "destination CIDR", which isn't
# a valid concept for INGRESS rules in GCP's model (unlike Azure NSGs/AWS
# security groups). Each tier's instances need the matching network tag
# (modules/gke tags its node pool "gke"); "gateway"/"data"/"mgmt" tags are
# reserved here for whatever compute later lands in those subnets.

resource "google_compute_firewall" "deny_all_ingress" {
  name      = "fw-${var.project_name}-deny-all-ingress-${var.environment}"
  network   = google_compute_network.this.name
  direction = "INGRESS"
  priority  = 65534
  deny {
    protocol = "all"
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_https_ingress_gateway" {
  name        = "fw-${var.project_name}-allow-https-gateway-${var.environment}"
  network     = google_compute_network.this.name
  direction   = "INGRESS"
  priority    = 1000
  target_tags = ["gateway"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_gateway_to_gke" {
  name        = "fw-${var.project_name}-allow-gateway-to-gke-${var.environment}"
  network     = google_compute_network.this.name
  direction   = "INGRESS"
  priority    = 1000
  target_tags = ["gke"]
  source_tags = ["gateway"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "allow_gke_to_data" {
  name        = "fw-${var.project_name}-allow-gke-to-data-${var.environment}"
  network     = google_compute_network.this.name
  direction   = "INGRESS"
  priority    = 1000
  target_tags = ["data"]
  # Same control as Azure's data-subnet NSG: only instances tagged "gke"
  # may reach this tier — nothing else, including the internet.
  source_tags = ["gke"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "allow_admin_to_mgmt" {
  count       = length(var.allowed_admin_cidrs) > 0 ? 1 : 0
  name        = "fw-${var.project_name}-allow-admin-mgmt-${var.environment}"
  network     = google_compute_network.this.name
  direction   = "INGRESS"
  priority    = 1000
  target_tags = ["mgmt"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = var.allowed_admin_cidrs
}
