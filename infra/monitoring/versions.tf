terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {
    grafana = {
      source  = "grafana/grafana"
      version = "= 4.45.2"
    }
  }
}
