# Service mesh module — Phase 4 (Zero Trust / mTLS), v1 spec §16.
#
# Closes RR-03/RR-04 (AUTHN-FLOW-01: "no application-layer authentication,
# just network reachability" for api-gateway -> payment/account/
# notification-service). Istio's mesh-wide STRICT PeerAuthentication is
# exactly the fix threat_engine.py's own mitigation text names: "Introduce
# a service mesh (mTLS)... between gateway and services." STRICT mode
# rejects any plaintext connection between sidecar-injected pods outright
# — this is real mutual TLS with workload-identity-bound certificates
# (SPIFFE), not just "the traffic happens to be encrypted."
#
# Identical in shape across all three clouds (terraform/{azure,gcp,aws}/
# modules/mesh) — Istio-on-Kubernetes doesn't care which cloud the
# cluster runs on. What differs per cloud is only how the helm/kubernetes
# providers authenticate to get there (see each cloud's providers.tf).

resource "helm_release" "istio_base" {
  name             = "istio-base"
  repository       = "https://istio-release.storage.googleapis.com/charts"
  chart            = "base"
  version          = var.istio_version
  namespace        = "istio-system"
  create_namespace = true
}

resource "helm_release" "istiod" {
  name       = "istiod"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "istiod"
  version    = var.istio_version
  namespace  = "istio-system"

  set {
    name  = "meshConfig.accessLogFile"
    value = "/dev/stdout"
  }

  depends_on = [helm_release.istio_base]
}

resource "kubernetes_namespace" "app" {
  metadata {
    name = var.app_namespace
    labels = {
      "istio-injection" = "enabled"
    }
  }
}

# Mesh-wide STRICT mTLS — a PeerAuthentication named "default" in the
# root namespace (istio-system) applies to every sidecar-injected
# workload in the mesh, not just var.app_namespace: any plaintext
# connection between mesh members is rejected outright, closing the
# "anything else that lands in the same subnet can impersonate the
# caller" threat AUTHN-FLOW-01 describes.
resource "kubernetes_manifest" "mesh_wide_mtls_strict" {
  manifest = {
    apiVersion = "security.istio.io/v1beta1"
    kind       = "PeerAuthentication"
    metadata = {
      name      = "default"
      namespace = "istio-system"
    }
    spec = {
      mtls = {
        mode = "STRICT"
      }
    }
  }

  depends_on = [helm_release.istiod]
}
