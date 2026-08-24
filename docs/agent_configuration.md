# VM-AuthN-Scope Guest Agent Configuration Reference

This document describes the configuration options available for the VM-AuthN-Scope Guest Agent (`authn-scope-agent`). The configuration is defined in JSON format (typically stored at `/etc/authn-scope/agent.json`).

For a complete example, see [agent.json](../config-examples/agent.json).

---

## Configuration Options

| Option | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `vm_name` | `string` | The human-readable name of this VM. Sent to the server in `CertRequest` to authorize caller. | *Required* |
| `server_port` | `integer` | The vsock port the host CA server is listening on. | `900` |
| `client_port` | `integer` | The client local port to bind to when dialing the host server. | `901` |
| `identities` | `array` | List of configuration entries for local services/processes needing certificates. See [Identity Entry Configuration](#Identity-entry-configuration) below. | `[]` |

---

## Identity Entry Configuration

Each entry in the `identities` array defines how a guest service requests its certificate and where its credentials are saved:

| Field | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `name` | `string` | The Identity identifier (must match the name registered under this VM's CID on the host CA config). | *Required* |
| `cert_path` | `string` | Absolute path where the signed certificate PEM will be saved. | *Required* |
| `key_path` | `string` | Absolute path where the generated private key PEM will be saved. | *Required* |
| `ca_path` | `string` | Absolute path where the host CA certificate PEM will be saved. | *Required* |
| `owner_uid` | `integer` | Unix UID to set on the written cert and key files. | `0` |
| `owner_gid` | `integer` | Unix GID to set on the written cert and key files. | `0` |
| `cert_mode` | `string` | Octal permission string for the certificate file. | `"0640"` |
| `key_mode` | `string` | Octal permission string for the private key file. | `"0600"` |
