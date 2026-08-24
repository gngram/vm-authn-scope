# VM-AuthN-Scope Host Server Configuration Reference

This document describes the configuration options available for the VM-AuthN-Scope Host Server (`authn-scope-server`). The configuration is defined in JSON format (typically stored at `/etc/authn-scope/host.json`).

For a complete example, see [host.json](../config-examples/host.json).

---

## Configuration Options

| Option | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `ca_cert_path` | `string` | Absolute path where the CA root certificate PEM will be loaded from or generated to. | *Required* |
| `ca_key_path` | `string` | Absolute path where the CA private key PEM will be loaded from or generated to. | *Required* |
| `server_port` | `integer` | The vsock port the server listens on (must be < 1000). | `900` |
| `peer_port` | `integer` | The expected source port of dialing guest agents. Incoming connections from other ports are dropped. | `901` |
| `cert_validity_days` | `integer` | Number of days for which issued guest certificates are valid. | `365` |
| `vms` | `object` | Map of VM configuration objects, keyed by VM name. See [VM Configuration](#vm-configuration) below. | `{}` |

---

## VM Configuration

Each key in the `vms` object is a string representing the guest VM's name (e.g., `"vm-frontend"`). The value is an object with the following schema:

| Field | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `vm_cid` | `integer` | The vsock CID of the guest VM (used by the host server to verify caller identity). | *Required* |
| `entities` | `object` | Map of entity names to their capability specifications. See [Entity & Capability Configuration](#entity--capability-configuration) below. | `{}` |

---

## Entity & Capability Configuration

Each key in the `entities` object is the name of a local service or process running on the guest VM (e.g., `"service-a"`). The value contains the capabilities embedded inside the issued certificate's custom extension JWT:

| Field | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `caps` | `array` | List of capability definitions. | `[]` |

### Capability Definition Schema

| Field | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `target_vm` | `string` | The target VM name where the capability is valid. | *Required* |
| `rpc_modules` | `array of strings` | List of allowed RPC modules (e.g., `["auth"]`). | `[]` |
| `rpc_methods` | `array of strings` | List of allowed RPC methods (e.g., `["data.read_secure"]`). | `[]` |
| `paths` | `array of objects` | List of path patterns and access rights. See [Path Access Schema](#path-access-schema) below. | `[]` |

### Path Access Schema

| Field | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `path` | `string` | Resource path pattern (e.g., `/api/v1/health`). | *Required* |
| `access` | `array of strings` | Allowed access modes (e.g., `["read"]`, `["write"]`). | *Required* |
