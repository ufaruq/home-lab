# Monitoring as code

**Superseding placement decision:** the owner subsequently selected Oracle for
the central Wazuh server. See [Oracle Wazuh design](2026-10-25-oracle-wazuh-design.md).
`oracle_wazuh` is now the explicit external manager target; the captured local VM
is preserved. Oracle free host capacity and private VPN setup block live rollout.
The original local-placement discussion below is historical context.

## Approved direction and intent

The user selected Grafana Cloud Free plus self-hosted Wazuh, asked to cover the repository's fleet, OPNsense and one or two small devices, accepted short retention, and explicitly requested implementation of configuration folders and automated deployment/redeployment for both systems. Grafana URL: https://cordialbike2680.grafana.net. A later screenshot superseded the initial Free answer: the observed stack is Trial. The Trial is unbilled and automatically transitions to Free; the controller permits an explicit Alloy-only collector deployment after live edition verification. Absolute cloud budget: $0, as required by AGENTS.md.

## Approach

Extend the existing Terraform/Ansible workflow. The primary infra/monitoring Terraform composition manages Grafana folders, dashboards and alert rules through a static child module, and invokes versioned Ansible roles through one creation-only terraform_data record for explicitly selected hosts. Ansible implements Alloy, Wazuh and OPNsense configuration. A monitoring controller validates an explicit fleet manifest, private deployment inputs and saved Terraform plans before invoking tools. Reuse the existing Ansible inventory; do not regenerate or overwrite captured host_vars. Native Terraform refresh does not detect arbitrary guest drift; deliberate record replacement re-converges guests. There is no automatic uninstall on record destruction.

Alternatives already discussed were Elastic/OpenSearch or self-hosting the entire observability backend. The user chose managed Grafana plus Wazuh for the combination of debugging visibility and endpoint security without subscriptions. Central Wazuh placement is the existing local VM by default (4 vCPU, 8 GiB, 100 GiB); Oracle provisioning is outside this change.

## Scope and boundaries

- Provide reusable code and verified local checks now. Live deployment requires actual target reachability and private credentials; do not invent addresses or credentials or claim live deployment without readback.
- Grafana resources must not create/upgrade cloud stacks, subscriptions, data sources with paid backends, hosted integrations or billing plans. Use existing Prometheus/Loki data sources. Do not take over global notification routing.
- Credentials stay in environment variables or owner-only private files outside the checkout. Generated credential-bearing files and logs are private; disable secret diffs and logs in Ansible. Preserve SSH and TLS verification.
- Use an explicit manifest referencing all 15 existing inventory names, including dom0 and the 14 VM definitions. Diskless definitions remain blocked, unverified appliance collection remains pending, and dom0 gets no third-party software. Group Linux/Windows collectors, the Wazuh server, OPNsense and generic syslog/SNMP targets explicitly.
- Deploy only selected, verified hosts, with an exact --limit and private inventory override. Never automatically boot guests, replace VM disks, restore captured secret archives, upgrade a whole OS, or overwrite unrelated application settings.
- Fresh Wazuh bootstrap and adoption of the captured 4.7.5 installation are distinct operations. Default adoption must not upgrade or reinstall central components. Explicit pinned fresh installation must be restart-safe; upgrades require a documented backup/review step.
- Wazuh policies, custom decoders/rules, centralized Linux/Windows agent configuration and index-retention policy are repository-owned. Preserve existing certificates, agent keys, unrelated rules, security credentials, and manager enrollment settings. Active response defaults disabled, particularly on Parrot and malware-lab targets.
- Collect a bounded host metric allowlist and selected service/application logs. Do not enable unrestricted container/Kubernetes collection. Use stable labels: job=homelab, host=<inventory_name>, environment=homelab or lab, role=<manifest role>.
- Free-tier planning ceilings: 7,000 active metric series, 500 MB/day total logs; operational targets, not billing caps. Grafana Free currently allows 10,000 active series and 50 GB/month logs, with 14 days retention. Wazuh alert retention starts at 7 days; do not enable archive-all logging or delete unrelated indices.
- Monitor fleet presence using a declared expected-host set so a single missing host is caught even while other hosts remain online. Add disk/memory views and alerts. Host up is scrape health, not Wazuh daemon health; service probes are not implemented. The optional Wazuh security view is disabled and requires a separately reviewed export unsupported by the current narrow Alloy source allowlist. SMTP/webhook credentials and alert recipients remain private; applying may enable notifications only to the owner's chosen existing contact point.
- Wazuh is intended to remain private with exact administrator and agent source restrictions, no WAN port forwards, and authenticated VPN access for remote clients. The current application stack does not configure VPN/firewall/NAT rules; network isolation needs verified topology and a separate Terraform-managed implementation. Hosted Grafana's public login endpoint does not become private through a local VPN or ingestion-token IP restriction. Document DDoS limits without guaranteeing availability.

## Deliverables

- monitoring/: fleet policy, private-input examples without secrets, Grafana dashboard sources, Wazuh shared configuration/rules/retention sources, deployment/recovery guide.
- infra/grafana/: pinned provider, externally authenticated existing-stack resources, dashboards and alert groups, validations and mock tests.
- infra/monitoring/: primary Terraform composition, explicit host selections, source fingerprints, no destroy-time guest mutations and mock boundary tests.
- ansible/roles/monitoring_alloy/: Linux and Windows installation/configuration/service management using official packages and explicit version pins, scoped log/metric pipelines, local config validation before restart.
- ansible/roles/monitoring_wazuh_manager/ and monitoring_wazuh_agent/: safe adoption/configuration, explicit fresh deployment path, Linux/Windows agents, centralized policy and index retention, preservation of existing identities.
- Ansible monitoring playbooks and explicit OPNsense syslog automation where the native API supports it; generic appliances remain agentless.
- scripts/monitoring/: controller commands for offline validation, selected-target preview/deploy, and Grafana saved-plan/apply with resource allowlisting. No generic shell hooks or automatic fleet-wide deployment.
- Make targets and meaningful tests for policy, target selection, credential handling, deployment gate behavior, template/config validity, and Terraform resource scope.

## Verification and handoff

Run controller unit tests, existing regression tests, Ansible syntax checks, rendered Alloy validation with an official validator where available, XML/JSON validation, and Grafana terraform fmt/validate/mock tests. A fresh independent review checks secret handling, free-tier boundaries, existing Wazuh preservation, and unsupported targets. Verify actual Grafana/host results only after the owner supplies private credentials and reachable target declarations; report remaining live blockers precisely.

## Builder decisions

Choose minimal role internals and compatible pinned tool/provider versions from official documentation. Existing source files may be changed only narrowly for Make targets/documentation; other ongoing Xen recovery/convergence work must be preserved. Do not automatically commit or publish unrelated untracked work.

## 2026-10-26 live deployment ruling

The instance API confirms Cloud Trial. Official Grafana terms state Trial use is never billed, the Free plan is always $0, and Trial automatically transitions to Free. Permit folder/dashboard metadata and selected Alloy collectors after a fresh live Trial check before plan and apply. The Trial collection path excludes Wazuh-manager/OPNsense mutation and alerts; it creates no paid cloud resources or subscriptions. Host credentials and target access remain explicit private prerequisites. This supersedes the earlier blanket Trial block without declaring the stack already Free.
