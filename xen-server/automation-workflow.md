# Controller workflow

Use a separate controller with Terraform, the pinned provider and the Ansible requirements. The hypervisor and guests do not need a new management agent. Serialize writes and preserve private state before applying changes.

## Private configuration

The public repository has no live defaults. Select reviewed inputs with:

| Variable | Input |
| --- | --- |
| `XEN_INVENTORY_FILE` | Private XenAPI snapshot |
| `XEN_POLICY_FILE` | Private desired-state JSON |
| `XEN_ANSIBLE_INVENTORY` | Generated private Ansible inventory |
| `XEN_HOST_VARS_FILE` | Optional private control-host variables |
| `XEN_CONNECTION_FILE` | Owner-only connection JSON outside the checkout |
| `ANSIBLE_PLAYBOOK_BIN` / `TERRAFORM_BIN` | Controller executables |
| `XEN_RUN_DIR` | Ignored owner-only runtime directory |
| `XEN_PRIVATE_VARS` | Reviewed private guest variables outside the checkout |

Connection JSON may supply `XEN_HOST`, `XEN_SSH_HOST_ALIAS`, `XEN_KNOWN_HOSTS_FILE`, `XEN_FORWARD_TARGET` and the supported API URL/authentication fields. The host-key file must be private and independently verified. A loopback API endpoint needs an explicit forwarding target. Do not copy a test fixture, invent a trusted host key or disable verification to pass preflight.

An ignored `.local/xen/connection-path` may point to the private connection file. Operator environment settings take precedence. Never publish connection files, passwords, tokens, SSH sockets, private variables, plans or Terraform state.

Native host helpers also require private policy: expected host/pool identities, the approved automatic-management VM set and reviewed stock-file digests. Networking requires a separate private profile. See [native recovery](../ansible/recovery/README.md) and [networking](../ansible/networking/README.md).

## Review and execution

```sh
make inventory       # Summarize the supplied snapshot, not live discovery.
make check           # Offline validation and synthetic tests.
make readiness       # Read live prerequisites using private configuration.
make plan            # Discover identities and guard a private saved plan.
make up              # Apply the checked plan and selected reviewed policies.
```

The convergence guard preserves stable logical ownership while checking current discovered/state-bound identities. It rejects deletion, replacement, unreviewed disk/NIC changes and unknown resources. Missing ordinary resources require verified recovery prerequisites; passthrough and physical-network recovery remain protected. A dependent recovery can require separate reviewed stages.

Management bootstrap uses existing private state and live identity checks before starting an appliance declared Running. Restore the correct private state first. A changed recovered identity can require explicit review of native startup policy; bootstrap success alone does not complete that review.

Guest enforcement is separate: only explicitly selected Linux targets with verified access, reviewed configuration and declared desired state can proceed. An empty selection means no guest configuration was applied. BSD and Windows observations do not become Linux policy.

## Operations and scheduling

Use `make health`, `make definitions-check`, `make recovery-check`, `make hardening-check` and `make network-check` for their documented comparisons. Guest audits/checks also require verified private access. A failed or unreachable check is not a clean result.

No public fixture authorizes a live action. No unattended apply should be inferred from these commands. If scheduling is wanted, begin with read-only drift checks and define result handling and recovery access before considering automatic correction.

Keep actual run results and recovery records privately in ignored paths. Local validation, adoption and idempotence are different claims from a successful full restore.
