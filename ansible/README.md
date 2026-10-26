# Ansible inventory and gated configuration

Public code accepts explicit private inputs. It contains no deployment inventory, real guest facts, connection addresses or apply policy. Invented inputs under `tests/fixtures/xen/` support offline tests and examples only.

## Generate inventory

```sh
python ansible/files/generate_inventory.py \
  --inventory tests/fixtures/xen/inventory.json \
  --captures tests/fixtures/xen/guest-inventory \
  --output .local/example-inventory
```

For a real deployment, substitute a privately captured XenAPI inventory and optional sanitized capture directory, then write to an ignored local output. Refresh capture integration with:

```sh
python ansible/files/integrate_offline.py \
  --inventory .local/xen/inventory.json \
  --captures .local/xen/guest-captures \
  --output .local/xen/ansible
```

Generated hardware definitions retain observed identities and unsupported attributes as evidence. Cached guest metrics remain unverified hints, not connection addresses. Capture history and newer read-only evidence stay distinct. Generated host variables and actual capture manifests are private.

Linux evidence can produce a proposed account/package/service baseline; it is not permission to apply it. Native package versions may require matching repositories or retained installers. BSD/Windows facts remain observed-only and must not enter Linux convergence. Hardware-only and missing-filesystem entries remain explicit gaps. Duplicate guest/host addresses on the same network must be resolved before starting affected guests or changing routing.

## Access and desired policy

Supply a separate owner-only private inventory/variables file for verified access and intended policy. Public/group defaults keep access, configuration verification and desired-state gates false. Selected Linux targets additionally need an exact explicit selection and actual Linux/non-control-domain verification before mutation.

Never infer an application from a VM label. Do not invent installer sources, license information or account policy. Preserve unrelated users/packages and review historical system accounts before recreating them. Private password hashes and selected application files require explicit declarations and validation; never commit them or replay an entire configuration archive.

```sh
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
ansible-inventory -i .local/xen/ansible/hosts.yml --graph
ansible-playbook -i .local/xen/ansible/hosts.yml \
  ansible/playbooks/converge-guests.yml --syntax-check
```

Syntax checks do not verify access or apply state. Guest audits require reviewed private access; their reports must stay private. An empty guest selection means no guest configuration was performed.

Native [recovery](recovery/README.md), [logging](hardening/README.md) and [networking](networking/README.md) have separate private policies and check/apply gates. Do not treat guest evidence as authorization to mutate the control host.
