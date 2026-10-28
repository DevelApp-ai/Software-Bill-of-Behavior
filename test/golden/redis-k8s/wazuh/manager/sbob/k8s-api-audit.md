# k8s API server audit ingestion — redis scope

The `kubernetes-api-access` signature rule (rulePolicies) lands with M4;
this document is the ingestion path delivered by M3 (TDS 4.4).

## API server: emit audit events

```yaml
# /etc/kubernetes/audit-policy.yaml (apiserver --audit-policy-file=...)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    users: ["system:kube-proxy"]     # reduce noise
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Metadata                  # everything else, cheap
```

## Ship to the manager (two supported options)

1. **Syslog** — a log shipper on a control-plane node (fluent-bit/vector
   reading `/var/log/kubernetes/audit.log`) forwards to the manager's syslog
   listener:

```xml
<!-- /var/ossec/etc/ossec.conf on the manager -->
<remote>
  <connection>syslog</connection>
  <port>5140</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.96.0.0/12</allowed-ips>
</remote>
```

2. **Agent-side localfile** — a Wazuh agent on a control-plane node:

```xml
<localfile>
  <location>/var/log/kubernetes/audit.log</location>
  <log_format>json</log_format>
</localfile>
```

Both paths land the audit JSON at the manager where the M4
`kubernetes-api-access` rule (json decoder, `kind: Event`,
`userAgent`/`verb`/`resource` fields) evaluates it.
