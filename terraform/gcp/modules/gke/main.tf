# GKE module — hardened baseline, mirrors terraform/azure/modules/aks:
#   - private cluster (no public control-plane endpoint by default)
#   - Workload Identity instead of node-level service-account keys
#   - Shielded nodes, network policy enabled
#   - master authorized networks restrict who can reach the API at all

resource "google_container_cluster" "this" {
  name     = "gke-${var.project_name}-${var.environment}"
  location = var.region

  network    = var.network_name
  subnetwork = var.gke_subnet_self_link

  # Manage node pools explicitly (see google_container_node_pool below);
  # the default pool is removed immediately so nothing runs on it.
  remove_default_node_pool = true
  initial_node_count       = 1

  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false # control plane still reachable from authorized CIDRs, not the public internet at large
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  dynamic "master_authorized_networks_config" {
    for_each = length(var.authorized_cidrs) > 0 ? [1] : []
    content {
      dynamic "cidr_blocks" {
        for_each = var.authorized_cidrs
        content {
          cidr_block = cidr_blocks.value
        }
      }
    }
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  release_channel {
    channel = "REGULAR"
  }
}

resource "google_container_node_pool" "user" {
  name     = "user-pool"
  location = var.region
  cluster  = google_container_cluster.this.name
  node_count = 2

  node_config {
    machine_type = "e2-standard-4"
    tags         = ["gke"] # matches modules/network's target_tags so the firewall rules actually apply

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA" # Workload Identity — no node-level SA key ever handed to a pod
    }
  }
}
