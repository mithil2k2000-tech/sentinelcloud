# Network module — trust-boundary layout for the simulated bank scenario.
#
# Subnets model distinct trust zones so NSGs can enforce least privilege
# between them, not just at the perimeter:
#
#   snet-gateway  — API Gateway / ingress only, internet-facing
#   snet-aks      — Kubernetes nodes running payment-service, account-service, etc.
#   snet-data     — private endpoints for Key Vault + Storage (no public access)
#   snet-mgmt     — bastion / admin access, reachable only from allowed_admin_cidrs

resource "azurerm_resource_group" "this" {
  name     = "rg-${var.project_name}-${var.environment}"
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-${var.project_name}-${var.environment}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  address_space       = [var.address_space]
  tags                = var.tags
}

locals {
  # Carve four /22s out of the /16 address space for headroom.
  base = cidrsubnet(var.address_space, 0, 0)

  subnets = {
    gateway = { cidr = cidrsubnet(var.address_space, 6, 0) } # 10.20.0.0/22
    aks     = { cidr = cidrsubnet(var.address_space, 6, 1) } # 10.20.4.0/22
    data    = { cidr = cidrsubnet(var.address_space, 6, 2) } # 10.20.8.0/22
    mgmt    = { cidr = cidrsubnet(var.address_space, 6, 3) } # 10.20.12.0/22
  }
}

resource "azurerm_subnet" "this" {
  for_each             = local.subnets
  name                 = "snet-${each.key}"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [each.value.cidr]

  # snet-data gets private-endpoint support so Key Vault/Storage never need
  # a public IP.
  private_endpoint_network_policies = each.key == "data" ? "Enabled" : "Disabled"
}

# --- Network Security Groups: deny-by-default, explicit allow only -------

resource "azurerm_network_security_group" "gateway" {
  name                = "nsg-${var.project_name}-gateway-${var.environment}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = var.tags

  security_rule {
    name                       = "AllowHttpsInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "aks" {
  name                = "nsg-${var.project_name}-aks-${var.environment}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = var.tags

  # Only the gateway subnet may reach the AKS node subnet — nothing else,
  # including the internet, can talk to nodes directly.
  security_rule {
    name                       = "AllowFromGatewaySubnet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = local.subnets.gateway.cidr
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "data" {
  name                = "nsg-${var.project_name}-data-${var.environment}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = var.tags

  # Only AKS-subnet workloads may reach the private-endpoint subnet holding
  # Key Vault / Storage. This is the control that stops "payment service has
  # unrestricted database/storage access" from the threat-model example.
  security_rule {
    name                       = "AllowFromAksSubnetOnly"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = local.subnets.aks.cidr
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "mgmt" {
  name                = "nsg-${var.project_name}-mgmt-${var.environment}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = var.tags

  dynamic "security_rule" {
    for_each = length(var.allowed_admin_cidrs) > 0 ? [1] : []
    content {
      name                       = "AllowAdminSsh"
      priority                   = 100
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefixes    = var.allowed_admin_cidrs
      destination_address_prefix = "*"
    }
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "this" {
  for_each  = azurerm_subnet.this
  subnet_id = each.value.id
  network_security_group_id = {
    gateway = azurerm_network_security_group.gateway.id
    aks     = azurerm_network_security_group.aks.id
    data    = azurerm_network_security_group.data.id
    mgmt    = azurerm_network_security_group.mgmt.id
  }[each.key]
}
