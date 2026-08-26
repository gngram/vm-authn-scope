//! Policy resolution: VM name + Identity → policy decision.

use crate::config::HostConfig;

/// Result of a policy lookup.
#[derive(Debug)]
pub struct PolicyDecision {
    pub vm_name: String,
    pub vm_cid: u32,
    pub ip: Option<String>,
    pub validity_seconds: u32,
}

/// Look up whether `vm_name`/`identity` is authorised and retrieve policy.
///
/// Returns `None` if the VM name is not in the config (reject the request).
/// Returns `None` if the identity is not registered for that VM.
pub fn resolve(config: &HostConfig, vm_name: &str, identity: &str) -> Option<PolicyDecision> {
    let vm_entry = config.vms.get(vm_name)?;
    let policy = vm_entry.identities.get(identity)?;

    let validity_seconds = policy.ttl_minutes * 60;

    Some(PolicyDecision {
        vm_name: vm_name.to_string(),
        vm_cid: vm_entry.vm_cid,
        ip: vm_entry.ip.clone(),
        validity_seconds,
    })
}
