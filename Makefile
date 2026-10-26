PYTHON ?= python3

.PHONY: inventory check plan up adopt adoption-plan readiness bootstrap audit definitions-check configure-check health hardening-check recovery-check network-check

inventory:
	$(PYTHON) scripts/xen/lab.py inventory

check:
	$(PYTHON) scripts/xen/lab.py validate

plan:
	$(PYTHON) scripts/xen/lab.py plan

# Reconcile declared resources, native definitions and selected guest policy.
up:
	$(PYTHON) scripts/xen/lab.py converge
	$(PYTHON) scripts/xen/xoa_access.py apply --if-configured

.PHONY: xoa-up xoa-status xoa-syntax
xoa-up:
	$(PYTHON) scripts/xen/xoa_access.py apply

xoa-status:
	$(PYTHON) scripts/xen/xoa_access.py status

xoa-syntax:
	$(PYTHON) scripts/xen/xoa_access.py syntax

.PHONY: xo-update xo-update-status xo-update-syntax
xo-update:
	$(PYTHON) scripts/xen/xoa_access.py source-update

xo-update-status:
	$(PYTHON) scripts/xen/xoa_access.py source-status

xo-update-syntax:
	$(PYTHON) scripts/xen/xoa_access.py source-syntax

adopt:
	$(PYTHON) scripts/xen/lab.py adopt

adoption-plan:
	$(PYTHON) scripts/xen/lab.py adoption-plan

readiness:
	$(PYTHON) scripts/xen/lab.py readiness

bootstrap:
	$(PYTHON) scripts/xen/lab.py bootstrap

audit:
	$(PYTHON) scripts/xen/lab.py audit

definitions-check:
	$(PYTHON) scripts/xen/lab.py definitions-check

configure-check:
	$(PYTHON) scripts/xen/lab.py configure-check

health:
	$(PYTHON) scripts/xen/lab.py health

hardening-check:
	$(PYTHON) scripts/xen/lab.py hardening-check

recovery-check:
	$(PYTHON) scripts/xen/lab.py recovery-check

network-check:
	$(PYTHON) scripts/xen/lab.py network-check

# Monitoring is orchestrated by infra/monitoring Terraform. Guest roles remain
# independently testable; these commands never select an implicit fleet.
MONITORING_ARGS ?=
.PHONY: monitoring-inventory monitoring-check monitoring-syntax monitoring-info monitoring-plan monitoring-up

monitoring-inventory:
	$(PYTHON) scripts/monitoring/manage.py inventory

monitoring-check:
	$(PYTHON) scripts/monitoring/manage.py validate --inventory tests/fixtures/monitoring/hosts.json
	$(PYTHON) -m unittest discover -s scripts/monitoring/tests -v
	node --test scripts/monitoring/tests/xcp_metrics.test.cjs scripts/monitoring/tests/xcp_runtime.test.cjs scripts/monitoring/tests/xcp_vms.test.cjs
	$(PYTHON) -m unittest discover -s ansible/tests -p 'test_monitoring_*.py' -v

monitoring-syntax:
	$(PYTHON) scripts/monitoring/manage.py syntax

monitoring-info:
	$(PYTHON) scripts/monitoring/manage.py grafana-info

monitoring-plan:
	$(PYTHON) scripts/monitoring/manage.py stack-plan $(MONITORING_ARGS)

monitoring-up:
	$(PYTHON) scripts/monitoring/manage.py stack-apply $(MONITORING_ARGS)

.PHONY: monitoring-xcp-plan monitoring-xcp-up monitoring-xcp-status
monitoring-xcp-plan:
	$(PYTHON) scripts/monitoring/xcp.py plan $(MONITORING_ARGS)

monitoring-xcp-up:
	$(PYTHON) scripts/monitoring/xcp.py apply $(MONITORING_ARGS)

monitoring-xcp-status:
	$(PYTHON) scripts/monitoring/xcp.py status

.PHONY: oracle-wazuh-check oracle-wazuh-audit oracle-wazuh-plan oracle-wazuh-up
oracle-wazuh-check:
	$(PYTHON) -m unittest discover -s scripts/oracle/tests -v
	terraform -chdir=infra/oracle/wazuh fmt -check -recursive
	terraform -chdir=infra/oracle/wazuh validate
	terraform -chdir=infra/oracle/wazuh test

oracle-wazuh-audit:
	$(PYTHON) scripts/oracle/wazuh.py audit

oracle-wazuh-plan:
	$(PYTHON) scripts/oracle/wazuh.py plan $(MONITORING_ARGS)

oracle-wazuh-up:
	$(PYTHON) scripts/oracle/wazuh.py apply $(MONITORING_ARGS)
