terraform {
  required_version = ">= 1.7.0, < 2.0.0"
  required_providers {
    xenorchestra = {
      source  = "vatesfr/xenorchestra"
      version = "0.41.2"
    }
  }
}
