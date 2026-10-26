terraform {
  required_version = ">= 1.7.0, < 2.0.0"
  required_providers {
    grafana = {
      source  = "grafana/grafana"
      version = "= 4.45.2"
    }
  }
}

# GRAFANA_URL and GRAFANA_AUTH are deliberately supplied only by the environment.
# This provider never receives Grafana Cloud account/billing credentials.
provider "grafana" {
  insecure_skip_verify = false
}
