//! Policy resolution: VM name + entity → capability list.

use authn_scope_proto::caps::Capability;

use crate::config::HostConfig;

/// Result of a policy lookup.
#[derive(Debug)]
pub struct PolicyDecision {
    pub vm_name: String,
    pub vm_cid: u32,
    pub caps: Vec<Capability>,
    pub validity_days: u32,
}

/// Look up whether `vm_name`/`entity` is authorised and retrieve capabilities.
///
/// Returns `None` if the VM name is not in the config (reject the request).
/// Returns `None` if the entity is not registered for that VM.
pub fn resolve(config: &HostConfig, vm_name: &str, entity: &str) -> Option<PolicyDecision> {
    let vm_entry = config.vms.get(vm_name)?;
    let policy = vm_entry.entities.get(entity)?;

    Some(PolicyDecision {
        vm_name: vm_name.to_string(),
        vm_cid: vm_entry.vm_cid,
        caps: policy.caps.clone(),
        validity_days: policy.validity_days.unwrap_or(config.cert_validity_days),
    })
}
