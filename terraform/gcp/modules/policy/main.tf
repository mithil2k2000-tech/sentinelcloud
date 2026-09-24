# Policy module — GCP Organization/Project Policy constraints. Same role as
# terraform/azure/modules/policy: turn a bad `terraform plan` into a
# blocked deployment, deterministically, no review required.

resource "google_project_organization_policy" "no_public_ip" {
  project    = var.project_id
  constraint = "constraints/compute.vmExternalIpAccess"

  list_policy {
    deny {
      all = true
    }
  }
}

resource "google_project_organization_policy" "restrict_public_buckets" {
  project    = var.project_id
  constraint = "constraints/storage.publicAccessPrevention"

  boolean_policy {
    enforced = true
  }
}

resource "google_project_organization_policy" "require_shielded_vm" {
  project    = var.project_id
  constraint = "constraints/compute.requireShieldedVm"

  boolean_policy {
    enforced = true
  }
}

resource "google_project_organization_policy" "restrict_sa_key_creation" {
  # Blocks anyone creating a long-lived downloadable service-account key —
  # forces workload identity / short-lived credentials instead, which is
  # what modules/gke and modules/iam already use.
  project    = var.project_id
  constraint = "constraints/iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}
