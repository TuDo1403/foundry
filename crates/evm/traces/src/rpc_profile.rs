//! Profilers for RPC-backed traces.

use crate::{CallKind, CallTraceArena, CallTraceNode, DecodedTraceStep};
use alloy_primitives::{Address, B256, U256, map::HashMap};
use revm::bytecode::opcode::OpCode;
use revm_inspectors::tracing::types::CallTraceStep;
use serde::{Deserialize, Serialize};

/// Profile sections emitted by `cast run --trace`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTraceProfiles {
    pub functions: Vec<FunctionProfile>,
    pub source_ranges: Vec<SourceRangeProfile>,
    pub opcodes: Vec<OpcodeProfile>,
    pub storage_slots: Vec<StorageSlotProfile>,
    pub transient_storage_slots: Vec<StorageSlotProfile>,
}

/// Gas attributed to an external or decoded internal function.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionProfile {
    pub contract_name: String,
    pub function_name: String,
    pub source_path: Option<String>,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    pub inclusive_gas: u64,
    pub self_gas: u64,
    pub op_count: u64,
    pub call_count: u64,
}

/// Placeholder for future source-range attribution.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRangeProfile {
    pub source_path: Option<String>,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    pub gas_used: u64,
    pub op_count: u64,
}

/// Gas/count by opcode.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpcodeProfile {
    pub opcode: String,
    pub count: u64,
    pub gas_used: u64,
}

/// Access counts and gas for a storage slot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageSlotProfile {
    pub storage_address: Address,
    pub code_address: Address,
    pub slot: B256,
    pub reads: u64,
    pub writes: u64,
    pub touches: u64,
    pub gas_used: u64,
    pub first_touch: Option<StorageTouch>,
    pub last_touch: Option<StorageTouch>,
    pub functions: Vec<String>,
}

/// Location of a storage touch.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageTouch {
    pub call_id: usize,
    pub contract_name: String,
    pub function_name: String,
    pub pc: usize,
    pub op: String,
}

/// Builds all `cast run --trace` profiles from a decoded arena.
pub fn profile_arena(arena: &CallTraceArena, include_storage: bool) -> RpcTraceProfiles {
    let mut profiles = RpcTraceProfiles::default();
    profiles.functions = profile_functions(arena);
    profiles.opcodes = profile_opcodes(arena);

    if include_storage {
        let (storage, transient) = profile_storage(arena);
        profiles.storage_slots = storage;
        profiles.transient_storage_slots = transient;
    }

    profiles
}

fn profile_functions(arena: &CallTraceArena) -> Vec<FunctionProfile> {
    let mut map: HashMap<(String, String), FunctionProfile> = HashMap::default();

    for node in arena.nodes() {
        let contract = contract_name(node);
        let function = function_name(node);
        let child_gas = node
            .children
            .iter()
            .filter_map(|idx| arena.nodes().get(*idx))
            .map(|child| child.trace.gas_used)
            .sum::<u64>();
        upsert_function(
            &mut map,
            contract,
            function,
            node.trace.gas_used,
            node.trace.gas_used.saturating_sub(child_gas),
            node.trace.steps.len() as u64,
        );

        for (step_idx, step) in node.trace.steps.iter().enumerate() {
            let Some(decoded) = &step.decoded else { continue };
            let DecodedTraceStep::InternalCall(call, end_idx) = &**decoded else { continue };
            let gas = node
                .trace
                .steps
                .get(*end_idx)
                .map(|end| gas_between_steps(step, end))
                .unwrap_or_default();
            let (contract, function) = call
                .func_name
                .split_once("::")
                .map(|(contract, function)| (contract.to_string(), function.to_string()))
                .unwrap_or_else(|| (contract_name(node), call.func_name.clone()));
            let op_count = end_idx.saturating_sub(step_idx) as u64;
            upsert_function(&mut map, contract, function, gas, gas, op_count);
        }
    }

    let mut functions = map.into_values().collect::<Vec<_>>();
    functions.sort_by(|a, b| {
        b.inclusive_gas
            .cmp(&a.inclusive_gas)
            .then_with(|| a.contract_name.cmp(&b.contract_name))
            .then_with(|| a.function_name.cmp(&b.function_name))
    });
    functions
}

fn gas_between_steps(start: &CallTraceStep, end: &CallTraceStep) -> u64 {
    let remaining_delta = start.gas_remaining.saturating_sub(end.gas_remaining);
    if remaining_delta == 0 { end.gas_used.saturating_sub(start.gas_used) } else { remaining_delta }
}

fn upsert_function(
    map: &mut HashMap<(String, String), FunctionProfile>,
    contract_name: String,
    function_name: String,
    inclusive_gas: u64,
    self_gas: u64,
    op_count: u64,
) {
    let entry = map
        .entry((contract_name.clone(), function_name.clone()))
        .or_insert_with(|| FunctionProfile { contract_name, function_name, ..Default::default() });
    entry.inclusive_gas = entry.inclusive_gas.saturating_add(inclusive_gas);
    entry.self_gas = entry.self_gas.saturating_add(self_gas);
    entry.op_count = entry.op_count.saturating_add(op_count);
    entry.call_count = entry.call_count.saturating_add(1);
}

fn profile_opcodes(arena: &CallTraceArena) -> Vec<OpcodeProfile> {
    let mut map: HashMap<String, OpcodeProfile> = HashMap::default();
    for step in arena.nodes().iter().flat_map(|node| &node.trace.steps) {
        let opcode = step.op.as_str().to_string();
        let entry = map
            .entry(opcode.clone())
            .or_insert_with(|| OpcodeProfile { opcode, ..Default::default() });
        entry.count += 1;
        entry.gas_used = entry.gas_used.saturating_add(step.gas_cost);
    }
    let mut opcodes = map.into_values().collect::<Vec<_>>();
    opcodes.sort_by(|a, b| b.gas_used.cmp(&a.gas_used).then_with(|| a.opcode.cmp(&b.opcode)));
    opcodes
}

fn profile_storage(arena: &CallTraceArena) -> (Vec<StorageSlotProfile>, Vec<StorageSlotProfile>) {
    let mut storage: HashMap<(Address, B256), StorageSlotProfile> = HashMap::default();
    let mut transient: HashMap<(Address, B256), StorageSlotProfile> = HashMap::default();

    for node in arena.nodes() {
        let storage_address = storage_address(node);
        let code_address = node.trace.address;
        for step in &node.trace.steps {
            let Some(slot) = storage_slot(step.op, step.stack.as_deref()) else {
                continue;
            };
            let is_transient = matches!(step.op, OpCode::TLOAD | OpCode::TSTORE);
            let target = if is_transient { &mut transient } else { &mut storage };
            let entry = target.entry((storage_address, slot)).or_insert_with(|| {
                StorageSlotProfile { storage_address, code_address, slot, ..Default::default() }
            });

            let touch = StorageTouch {
                call_id: node.idx,
                contract_name: contract_name(node),
                function_name: function_name(node),
                pc: step.pc,
                op: step.op.as_str().to_string(),
            };

            match step.op {
                OpCode::SLOAD | OpCode::TLOAD => entry.reads += 1,
                OpCode::SSTORE | OpCode::TSTORE => entry.writes += 1,
                _ => {}
            }
            entry.touches += 1;
            entry.gas_used = entry.gas_used.saturating_add(step.gas_cost);
            if entry.first_touch.is_none() {
                entry.first_touch = Some(touch.clone());
            }
            entry.last_touch = Some(touch.clone());
            entry.functions.push(format!("{}::{}", touch.contract_name, touch.function_name));
        }
    }

    (finalize_storage(storage), finalize_storage(transient))
}

fn finalize_storage(map: HashMap<(Address, B256), StorageSlotProfile>) -> Vec<StorageSlotProfile> {
    let mut slots = map
        .into_values()
        .map(|mut slot| {
            slot.functions.sort();
            slot.functions.dedup();
            slot
        })
        .collect::<Vec<_>>();
    slots.sort_by(|a, b| {
        b.touches
            .cmp(&a.touches)
            .then_with(|| b.gas_used.cmp(&a.gas_used))
            .then_with(|| a.storage_address.cmp(&b.storage_address))
            .then_with(|| a.slot.cmp(&b.slot))
    });
    slots
}

fn storage_slot(op: OpCode, stack: Option<&[U256]>) -> Option<B256> {
    if !matches!(op, OpCode::SLOAD | OpCode::SSTORE | OpCode::TLOAD | OpCode::TSTORE) {
        return None;
    }
    let slot = *stack?.last()?;
    Some(B256::from(slot.to_be_bytes::<32>()))
}

fn storage_address(node: &CallTraceNode) -> Address {
    if matches!(node.trace.kind, CallKind::DelegateCall | CallKind::CallCode) {
        node.trace.caller
    } else {
        node.trace.address
    }
}

fn contract_name(node: &CallTraceNode) -> String {
    node.trace
        .decoded
        .as_deref()
        .and_then(|decoded| decoded.label.clone())
        .unwrap_or_else(|| node.trace.address.to_string())
}

fn function_name(node: &CallTraceNode) -> String {
    node.trace
        .decoded
        .as_deref()
        .and_then(|decoded| decoded.call_data.as_ref())
        .map(|call_data| {
            call_data
                .signature
                .split_once('(')
                .map(|(name, _)| name)
                .unwrap_or(&call_data.signature)
                .to_string()
        })
        .unwrap_or_else(|| {
            node.selector()
                .map(|selector| format!("{selector:?}"))
                .unwrap_or_else(|| "<fallback>".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CallTrace;
    use alloy_primitives::{address, bytes};

    #[test]
    fn extracts_sload_and_sstore_slots() {
        let slot = U256::from(0x1234);
        assert_eq!(
            storage_slot(OpCode::SLOAD, Some(&[slot])),
            Some(B256::from(slot.to_be_bytes::<32>()))
        );
        assert_eq!(
            storage_slot(OpCode::SSTORE, Some(&[U256::from(1), slot])),
            Some(B256::from(slot.to_be_bytes::<32>()))
        );
        assert_eq!(
            storage_slot(OpCode::TLOAD, Some(&[slot])),
            Some(B256::from(slot.to_be_bytes::<32>()))
        );
        assert_eq!(
            storage_slot(OpCode::TSTORE, Some(&[U256::from(1), slot])),
            Some(B256::from(slot.to_be_bytes::<32>()))
        );
    }

    #[test]
    fn ranks_hot_storage_slots() {
        let addr = address!("0000000000000000000000000000000000000001");
        let mut arena = CallTraceArena::default();
        arena.nodes_mut()[0].trace = CallTrace {
            address: addr,
            success: true,
            steps: vec![
                CallTraceStep {
                    op: OpCode::SLOAD,
                    stack: Some(vec![U256::from(1)].into_boxed_slice()),
                    gas_cost: 2100,
                    ..empty_step()
                },
                CallTraceStep {
                    op: OpCode::SSTORE,
                    stack: Some(vec![U256::from(2), U256::from(1)].into_boxed_slice()),
                    gas_cost: 5000,
                    ..empty_step()
                },
            ],
            ..Default::default()
        };

        let profiles = profile_arena(&arena, true);
        assert_eq!(profiles.storage_slots.len(), 1);
        assert_eq!(profiles.storage_slots[0].reads, 1);
        assert_eq!(profiles.storage_slots[0].writes, 1);
        assert_eq!(profiles.storage_slots[0].gas_used, 7100);
    }

    #[test]
    fn separates_delegatecall_code_and_storage_addresses() {
        let proxy = address!("0000000000000000000000000000000000000001");
        let implementation = address!("0000000000000000000000000000000000000002");
        let mut arena = CallTraceArena::default();
        arena.nodes_mut()[0].trace = CallTrace {
            caller: proxy,
            address: implementation,
            kind: CallKind::DelegateCall,
            success: true,
            steps: vec![CallTraceStep {
                op: OpCode::SLOAD,
                stack: Some(vec![U256::from(1)].into_boxed_slice()),
                gas_cost: 2100,
                ..empty_step()
            }],
            ..Default::default()
        };

        let profiles = profile_arena(&arena, true);
        assert_eq!(profiles.storage_slots.len(), 1);
        assert_eq!(profiles.storage_slots[0].storage_address, proxy);
        assert_eq!(profiles.storage_slots[0].code_address, implementation);
    }

    #[test]
    fn reports_transient_storage_separately() {
        let addr = address!("0000000000000000000000000000000000000001");
        let mut arena = CallTraceArena::default();
        arena.nodes_mut()[0].trace = CallTrace {
            address: addr,
            success: true,
            steps: vec![
                CallTraceStep {
                    op: OpCode::TLOAD,
                    stack: Some(vec![U256::from(1)].into_boxed_slice()),
                    gas_cost: 100,
                    ..empty_step()
                },
                CallTraceStep {
                    op: OpCode::TSTORE,
                    stack: Some(vec![U256::from(2), U256::from(1)].into_boxed_slice()),
                    gas_cost: 100,
                    ..empty_step()
                },
            ],
            ..Default::default()
        };

        let profiles = profile_arena(&arena, true);
        assert!(profiles.storage_slots.is_empty());
        assert_eq!(profiles.transient_storage_slots.len(), 1);
        assert_eq!(profiles.transient_storage_slots[0].reads, 1);
        assert_eq!(profiles.transient_storage_slots[0].writes, 1);
    }

    #[test]
    fn aggregates_external_function_gas() {
        let root_addr = address!("0000000000000000000000000000000000000001");
        let child_addr = address!("0000000000000000000000000000000000000002");
        let mut arena = CallTraceArena::default();
        arena.nodes_mut()[0].children = vec![1];
        arena.nodes_mut()[0].trace = CallTrace {
            address: root_addr,
            data: bytes!("aaaaaaaa"),
            gas_used: 100,
            steps: vec![empty_step(), empty_step()],
            ..Default::default()
        };
        arena.nodes_mut().push(CallTraceNode {
            parent: Some(0),
            idx: 1,
            trace: CallTrace {
                address: child_addr,
                data: bytes!("bbbbbbbb"),
                gas_used: 30,
                steps: vec![empty_step()],
                ..Default::default()
            },
            ..Default::default()
        });

        let profiles = profile_arena(&arena, false);
        let root = profiles
            .functions
            .iter()
            .find(|function| function.contract_name == root_addr.to_string())
            .expect("root profile exists");
        assert_eq!(root.inclusive_gas, 100);
        assert_eq!(root.self_gas, 70);
        assert_eq!(root.op_count, 2);
    }

    fn empty_step() -> CallTraceStep {
        CallTraceStep {
            pc: 0,
            op: OpCode::STOP,
            stack: None,
            push_stack: None,
            memory: None,
            returndata: Default::default(),
            gas_remaining: 0,
            gas_refund_counter: 0,
            gas_used: 0,
            gas_cost: 0,
            storage_change: None,
            status: None,
            immediate_bytes: None,
            decoded: None,
        }
    }
}
