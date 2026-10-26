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
