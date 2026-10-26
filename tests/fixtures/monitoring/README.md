# Monitoring policy fixture

`hosts.json` contains only public aliases from the monitoring policy, with empty
host variables. It has no captured inventory, addresses, UUIDs, credentials or
access grants and cannot deploy a collector. Offline validation and tests use it
so a clean clone does not need private lab files. Live deployment still requires
the ignored operator inventory and verified private deployment inputs.
