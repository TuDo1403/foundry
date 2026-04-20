//! Helpers for reconstructing Foundry trace data from `debug_traceTransaction` RPC responses.

use crate::{
    CallKind, CallLog, CallTrace, CallTraceArena, CallTraceNode, DecodedTraceStep,
    SparsedTraceArena, TraceMemberOrder,
};
use alloy_primitives::{Address, Bytes, LogData, U256};
use alloy_rpc_types::trace::geth::{CallFrame, DefaultFrame, StructLog};
use revm::{
    bytecode::opcode::{self, OpCode},
    interpreter::InstructionResult,
};
use revm_inspectors::tracing::types::CallTraceStep;
use serde::{Deserialize, Serialize};

/// Result of converting RPC traces into Foundry's trace arena.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTraceArena {
    pub arena: SparsedTraceArena,
    pub warnings: Vec<String>,
}

/// JSON-friendly representation of a decoded trace.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcJsonTrace {
    pub root_call_id: usize,
    pub calls: Vec<RpcJsonCall>,
}

/// JSON-friendly call frame derived from a decoded Foundry trace node.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcJsonCall {
    pub id: usize,
    pub parent_id: Option<usize>,
    pub depth: usize,
    #[serde(rename = "type")]
    pub call_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_name: Option<String>,
    pub from: Address,
    pub to: Address,
    pub code_address: Address,
    pub storage_address: Address,
    pub value: U256,
    pub input: Bytes,
    pub output: Bytes,
    pub selector: Option<String>,
    pub signature: Option<String>,
    pub gas: u64,
    pub gas_used: u64,
    pub success: bool,
    pub children: Vec<usize>,
    pub internal_frames: Vec<RpcJsonInternalFrame>,
}

/// JSON-friendly internal function frame.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcJsonInternalFrame {
    pub function_name: String,
    pub start_step: usize,
    pub end_step: usize,
    pub gas_used: u64,
}

/// Converts geth's call tracer and struct logger outputs into a Foundry trace arena.
pub fn build_rpc_trace_arena(
    call_frame: &CallFrame,
    default_frame: &DefaultFrame,
    trace_printer: bool,
) -> RpcTraceArena {
    let mut arena = CallTraceArena::default();
    let mut warnings = Vec::new();
    let root_idx = push_call_frame(&mut arena, None, call_frame, 0);
    debug_assert_eq!(root_idx, 0);

    assign_struct_logs(&mut arena, &default_frame.struct_logs, trace_printer, &mut warnings);
    append_unvisited_children(&mut arena);
    append_call_logs(&mut arena, call_frame);

    RpcTraceArena { arena: SparsedTraceArena { arena, ignored: Default::default() }, warnings }
}

/// Builds a hybrid arena using the remote call tracer for the call tree and a local replay for
/// opcode steps and ordering.
pub fn graft_local_replay_onto_call_tracer(
    call_frame: &CallFrame,
    local: &CallTraceArena,
) -> Option<RpcTraceArena> {
    if local.nodes().is_empty() {
        return None;
    }

    let mut merged = build_rpc_trace_arena(call_frame, &DefaultFrame::default(), false);
    if !nodes_match_relaxed(&merged.arena.arena.nodes()[0], &local.nodes()[0]) {
        push_unique_warning(
            &mut merged.warnings,
            "callTracer root diverged from local replay; falling back to pure local replay"
                .to_string(),
        );
        return None;
    }
    if !nodes_match_exact(&merged.arena.arena.nodes()[0], &local.nodes()[0]) {
        push_unique_warning(
            &mut merged.warnings,
            "callTracer root differed slightly from local replay; preserving remote call metadata while grafting local opcode steps".to_string(),
        );
    }

    graft_local_node(0, 0, &mut merged.arena.arena, local, &mut merged.warnings);
    Some(merged)
}

/// Normalizes and validates an RPC-derived trace arena against the transaction receipt.
pub fn finalize_rpc_trace_arena(
    arena: &mut CallTraceArena,
    receipt_gas_used: u64,
    warnings: &mut Vec<String>,
) {
    if let Some(root) = arena.nodes_mut().first_mut()
        && root.trace.gas_used != receipt_gas_used
    {
        push_unique_warning(
            warnings,
            format!(
                "root callTracer gasUsed ({}) differs from receipt gasUsed ({receipt_gas_used}); using receipt gas for root trace",
                root.trace.gas_used
            ),
        );
        root.trace.gas_used = receipt_gas_used;
    }

    validate_trace_arena(arena, warnings);
}

/// Converts a decoded Foundry arena into the stable JSON trace shape used by `cast run --trace`.
pub fn json_trace_from_arena(arena: &CallTraceArena) -> RpcJsonTrace {
    let calls = arena.nodes().iter().map(json_call_from_node).collect();
    RpcJsonTrace { root_call_id: 0, calls }
}

fn json_call_from_node(node: &CallTraceNode) -> RpcJsonCall {
    let signature = node
        .trace
        .decoded
        .as_deref()
        .and_then(|decoded| decoded.call_data.as_ref())
        .map(|call_data| call_data.signature.clone());
    let selector = node.selector().map(|selector| format!("{selector:?}"));
    let internal_frames = node
        .trace
        .steps
        .iter()
        .enumerate()
        .filter_map(|(idx, step)| {
            let DecodedTraceStep::InternalCall(call, end_step) = &**step.decoded.as_ref()? else {
                return None;
            };
            Some(RpcJsonInternalFrame {
                function_name: call.func_name.clone(),
                start_step: idx,
                end_step: *end_step,
                gas_used: node
                    .trace
                    .steps
                    .get(*end_step)
                    .map(|end| gas_between_steps(step, end))
                    .unwrap_or_default(),
            })
        })
        .collect();

    RpcJsonCall {
        id: node.idx,
        parent_id: node.parent,
        depth: node.trace.depth,
        call_type: node.trace.kind.to_string(),
        contract_name: node.trace.decoded.as_deref().and_then(|decoded| decoded.label.clone()),
        from: node.trace.caller,
        to: node.trace.address,
        code_address: node.trace.address,
        storage_address: storage_address(node),
        value: node.trace.value,
        input: node.trace.data.clone(),
        output: node.trace.output.clone(),
        selector,
        signature,
        gas: node.trace.gas_limit,
        gas_used: node.trace.gas_used,
        success: node.trace.success,
        children: node.children.clone(),
        internal_frames,
    }
}

fn gas_between_steps(start: &CallTraceStep, end: &CallTraceStep) -> u64 {
    end.gas_used.saturating_sub(start.gas_used)
}

fn graft_local_node(
    remote_idx: usize,
    local_idx: usize,
    remote: &mut CallTraceArena,
    local: &CallTraceArena,
    warnings: &mut Vec<String>,
) {
    let remote_children = remote.nodes()[remote_idx].children.clone();
    let remote_logs = remote.nodes()[remote_idx].logs.clone();
    let local_node = local.nodes()[local_idx].clone();

    let child_matches = match_child_nodes(
        remote_idx,
        &remote_children,
        local,
        &local_node.children,
        remote,
        warnings,
    );
    let mut ordered_remote_children = Vec::with_capacity(remote_children.len());
    let mut matched_remote_children = Vec::with_capacity(child_matches.len());
    let mut local_pos_to_remote_pos = vec![None; local_node.children.len()];
    let mut matched_remote_mask = vec![false; remote_children.len()];

    for (local_pos, remote_pos, local_child_idx) in &child_matches {
        local_pos_to_remote_pos[*local_pos] = Some(ordered_remote_children.len());
        ordered_remote_children.push(remote_children[*remote_pos]);
        matched_remote_children.push((remote_children[*remote_pos], *local_child_idx));
        matched_remote_mask[*remote_pos] = true;
    }
    for (remote_pos, remote_child_idx) in remote_children.iter().copied().enumerate() {
        if !matched_remote_mask[remote_pos] {
            ordered_remote_children.push(remote_child_idx);
        }
    }

    let remote_node = &mut remote.nodes_mut()[remote_idx];
    remote_node.children = ordered_remote_children;
    remote_node.trace.steps = local_node.trace.steps.clone();
    remote_node.logs = local_node.logs.clone();
    if remote_logs.len() > remote_node.logs.len() {
        remote_node.logs.extend(remote_logs[remote_node.logs.len()..].iter().cloned());
        push_unique_warning(
            warnings,
            format!(
                "node {remote_idx} had {} extra callTracer logs not seen in local replay; appended them after local ordering",
                remote_logs.len() - local_node.logs.len()
            ),
        );
    }

    let mut ordering = Vec::with_capacity(
        local_node.ordering.len()
            + remote_node.children.len().saturating_sub(child_matches.len())
            + remote_node.logs.len().saturating_sub(local_node.logs.len()),
    );
    for item in &local_node.ordering {
        match item {
            TraceMemberOrder::Step(step_idx) => ordering.push(TraceMemberOrder::Step(*step_idx)),
            TraceMemberOrder::Log(log_idx) => {
                if *log_idx < remote_node.logs.len() {
                    ordering.push(TraceMemberOrder::Log(*log_idx));
                } else {
                    push_unique_warning(
                        warnings,
                        format!("node {remote_idx} local replay referenced missing log {log_idx}"),
                    );
                }
            }
            TraceMemberOrder::Call(local_child_pos) => {
                if let Some(remote_child_pos) =
                    local_pos_to_remote_pos.get(*local_child_pos).and_then(|pos| *pos)
                {
                    ordering.push(TraceMemberOrder::Call(remote_child_pos));
                } else {
                    push_unique_warning(
                        warnings,
                        format!(
                            "node {remote_idx} had a local child at position {local_child_pos} that was not present in callTracer"
                        ),
                    );
                }
            }
        }
    }

    for remote_child_pos in child_matches.len()..remote_node.children.len() {
        ordering.push(TraceMemberOrder::Call(remote_child_pos));
    }
    for remote_log_pos in local_node.logs.len()..remote_node.logs.len() {
        ordering.push(TraceMemberOrder::Log(remote_log_pos));
    }
    remote_node.ordering = ordering;

    for (remote_child_idx, local_child_idx) in matched_remote_children {
        graft_local_node(remote_child_idx, local_child_idx, remote, local, warnings);
    }
}

fn match_child_nodes(
    remote_parent_idx: usize,
    remote_children: &[usize],
    local: &CallTraceArena,
    local_children: &[usize],
    remote: &CallTraceArena,
    warnings: &mut Vec<String>,
) -> Vec<(usize, usize, usize)> {
    let mut matches = Vec::new();
    let mut claimed_remote = vec![false; remote_children.len()];

    for (local_pos, local_child_idx) in local_children.iter().copied().enumerate() {
        let local_child = &local.nodes()[local_child_idx];
        let mut match_pos = find_matching_child(
            remote_children,
            &claimed_remote,
            remote,
            local_child,
            nodes_match_exact,
        );
        if match_pos.is_none() {
            match_pos = find_matching_child(
                remote_children,
                &claimed_remote,
                remote,
                local_child,
                nodes_match_relaxed,
            );
        }
        if match_pos.is_none()
            && local_pos < remote_children.len()
            && !claimed_remote[local_pos]
            && nodes_match_shallow(&remote.nodes()[remote_children[local_pos]], local_child)
        {
            match_pos = Some(local_pos);
        }

        if let Some(remote_pos) = match_pos {
            claimed_remote[remote_pos] = true;
            matches.push((local_pos, remote_pos, local_child_idx));
        } else {
            push_unique_warning(
                warnings,
                format!(
                    "node {remote_parent_idx} local child at position {local_pos} could not be matched to a callTracer child"
                ),
            );
        }
    }

    if remote_children.len() != local_children.len() {
        push_unique_warning(
            warnings,
            format!(
                "node {remote_parent_idx} child count differed between callTracer ({}) and local replay ({})",
                remote_children.len(),
                local_children.len()
            ),
        );
    }

    matches
}

fn find_matching_child(
    remote_children: &[usize],
    claimed_remote: &[bool],
    remote: &CallTraceArena,
    local_child: &CallTraceNode,
    predicate: fn(&CallTraceNode, &CallTraceNode) -> bool,
) -> Option<usize> {
    remote_children
        .iter()
        .enumerate()
        .find(|(remote_pos, remote_child_idx)| {
            !claimed_remote[*remote_pos]
                && predicate(&remote.nodes()[**remote_child_idx], local_child)
        })
        .map(|(remote_pos, _)| remote_pos)
}

fn nodes_match_exact(remote: &CallTraceNode, local: &CallTraceNode) -> bool {
    remote.trace.kind == local.trace.kind
        && remote.trace.caller == local.trace.caller
        && remote.trace.address == local.trace.address
        && remote.trace.value == local.trace.value
        && remote.trace.data == local.trace.data
}

fn nodes_match_relaxed(remote: &CallTraceNode, local: &CallTraceNode) -> bool {
    nodes_match_shallow(remote, local)
        && (remote.trace.kind.is_any_create() || remote.selector() == local.selector())
}

fn nodes_match_shallow(remote: &CallTraceNode, local: &CallTraceNode) -> bool {
    remote.trace.kind == local.trace.kind
        && remote.trace.caller == local.trace.caller
        && remote.trace.address == local.trace.address
        && remote.trace.value == local.trace.value
}

fn push_call_frame(
    arena: &mut CallTraceArena,
    parent: Option<usize>,
    frame: &CallFrame,
    depth: usize,
) -> usize {
    let idx = if depth == 0 {
        0
    } else {
        let idx = arena.nodes().len();
        arena.nodes_mut().push(CallTraceNode { parent, idx, ..Default::default() });
        if let Some(parent_idx) = parent {
            arena.nodes_mut()[parent_idx].children.push(idx);
        }
        idx
    };

    let success = frame.error.is_none() && frame.revert_reason.is_none();
    let kind = parse_call_kind(&frame.typ);
    let trace = CallTrace {
        depth,
        success,
        caller: frame.from,
        address: frame.to.unwrap_or_default(),
        kind,
        value: frame.value.unwrap_or_default(),
        data: frame.input.clone(),
        output: frame.output.clone().unwrap_or_default(),
        gas_used: frame.gas_used.saturating_to::<u64>(),
        gas_limit: frame.gas.saturating_to::<u64>(),
        status: Some(if success { InstructionResult::Return } else { InstructionResult::Revert }),
        ..Default::default()
    };
    arena.nodes_mut()[idx].trace = trace;

    for child in &frame.calls {
        push_call_frame(arena, Some(idx), child, depth + 1);
    }

    idx
}

fn assign_struct_logs(
    arena: &mut CallTraceArena,
    logs: &[StructLog],
    trace_printer: bool,
    warnings: &mut Vec<String>,
) {
    if logs.is_empty() {
        return;
    }

    let depth_offset = usize::from(logs[0].depth > 0);
    let mut active = vec![0usize];
    let mut next_child = vec![0usize; arena.nodes().len()];
    let mut initial_gas = vec![None::<u64>; arena.nodes().len()];

    for log in logs {
        let call_depth = (log.depth as usize).saturating_sub(depth_offset);

        if active.len() > call_depth + 1 {
            active.truncate(call_depth + 1);
        }

        while active.len() <= call_depth {
            let parent_idx = *active.last().unwrap_or(&0);
            let child_pos = next_child[parent_idx];
            let Some(child_idx) = arena.nodes()[parent_idx].children.get(child_pos).copied() else {
                push_unique_warning(
                    warnings,
                    format!(
                        "opcode depth {} had no matching callTracer child under node {}",
                        log.depth, parent_idx
                    ),
                );
                break;
            };
            arena.nodes_mut()[parent_idx].ordering.push(TraceMemberOrder::Call(child_pos));
            next_child[parent_idx] += 1;
            active.push(child_idx);
        }

        let node_idx = active.get(call_depth).copied().unwrap_or_else(|| *active.last().unwrap());
        let entry_gas = initial_gas[node_idx].get_or_insert(log.gas);
        let gas_used =
            rpc_step_gas_used(*entry_gas, log.gas, log.refund_counter.unwrap_or_default());
        let step = struct_log_to_step(log, trace_printer, warnings, gas_used);
        let step_idx = arena.nodes()[node_idx].trace.steps.len();
        let node = &mut arena.nodes_mut()[node_idx];
        node.trace.steps.push(step);
        node.ordering.push(TraceMemberOrder::Step(step_idx));
    }
}

fn rpc_step_gas_used(initial_gas: u64, gas_remaining: u64, refund_counter: u64) -> u64 {
    let spent = initial_gas.saturating_sub(gas_remaining);

    // RPC struct logs do not expose the active hardfork, so use the post-London refund cap that
    // matches modern chains and Foundry's local replay for current transactions.
    spent.saturating_sub(refund_counter.min(spent / 5))
}

fn validate_trace_arena(arena: &CallTraceArena, warnings: &mut Vec<String>) {
    for node in arena.nodes() {
        let mut prev_step_gas_used = None;

        for (step_idx, step) in node.trace.steps.iter().enumerate() {
            if let Some(prev) = prev_step_gas_used
                && step.gas_used < prev
            {
                push_unique_warning(
                    warnings,
                    format!(
                        "node {} step {} gasUsed ({}) decreased from previous step gasUsed ({prev})",
                        node.idx, step_idx, step.gas_used
                    ),
                );
            }

            if step.gas_used > node.trace.gas_used {
                push_unique_warning(
                    warnings,
                    format!(
                        "node {} step {} gasUsed ({}) exceeds enclosing call gasUsed ({})",
                        node.idx, step_idx, step.gas_used, node.trace.gas_used
                    ),
                );
            }

            if let Some(decoded) = &step.decoded
                && let DecodedTraceStep::InternalCall(call, end_idx) = &**decoded
            {
                let Some(end_step) = node.trace.steps.get(*end_idx) else {
                    push_unique_warning(
                        warnings,
                        format!(
                            "node {} internal frame '{}' has out-of-bounds end step {}",
                            node.idx, call.func_name, end_idx
                        ),
                    );
                    prev_step_gas_used = Some(step.gas_used);
                    continue;
                };

                let frame_gas_used = gas_between_steps(step, end_step);
                if frame_gas_used > node.trace.gas_used {
                    push_unique_warning(
                        warnings,
                        format!(
                            "node {} internal frame '{}' gasUsed ({frame_gas_used}) exceeds enclosing call gasUsed ({})",
                            node.idx, call.func_name, node.trace.gas_used
                        ),
                    );
                }
            }

            prev_step_gas_used = Some(step.gas_used);
        }
    }
}

fn append_unvisited_children(arena: &mut CallTraceArena) {
    for idx in 0..arena.nodes().len() {
        let existing_calls = arena.nodes()[idx]
            .ordering
            .iter()
            .filter_map(|item| match item {
                TraceMemberOrder::Call(child_pos) => Some(*child_pos),
                _ => None,
            })
            .max()
            .map_or(0, |max| max + 1);
        let child_count = arena.nodes()[idx].children.len();
        for child_pos in existing_calls..child_count {
            arena.nodes_mut()[idx].ordering.push(TraceMemberOrder::Call(child_pos));
        }
    }
}

fn append_call_logs(arena: &mut CallTraceArena, root: &CallFrame) {
    fn walk(arena: &mut CallTraceArena, frame: &CallFrame, idx: usize) {
        for log_frame in &frame.logs {
            let raw = log_frame.clone().into_log();
            let log_idx = arena.nodes()[idx].logs.len();
            let mut log = CallLog {
                address: raw.address,
                raw_log: LogData::new_unchecked(raw.data.topics().to_vec(), raw.data.data),
                decoded: None,
                position: log_frame.position.unwrap_or_default(),
                index: log_frame.index.unwrap_or_default(),
            };
            log.position = log_frame.position.unwrap_or(log.position);
            log.index = log_frame.index.unwrap_or(log.index);
            let node = &mut arena.nodes_mut()[idx];
            node.logs.push(log);
            node.ordering.push(TraceMemberOrder::Log(log_idx));
        }

        let children = arena.nodes()[idx].children.clone();
        for (child_frame, child_idx) in frame.calls.iter().zip(children) {
            walk(arena, child_frame, child_idx);
        }
    }

    walk(arena, root, 0);
}

fn struct_log_to_step(
    log: &StructLog,
    trace_printer: bool,
    warnings: &mut Vec<String>,
    gas_used: u64,
) -> CallTraceStep {
    let op = opcode_from_name(log.opcode()).unwrap_or_else(|| {
        push_unique_warning(warnings, format!("unsupported opcode in RPC trace: {}", log.opcode()));
        OpCode::STOP
    });
    CallTraceStep {
        pc: log.pc as usize,
        op,
        stack: log.stack.clone().map(Vec::into_boxed_slice),
        push_stack: None,
        memory: None,
        returndata: log.return_data.clone().unwrap_or_default(),
        gas_remaining: log.gas,
        gas_refund_counter: log.refund_counter.unwrap_or_default(),
        gas_used,
        gas_cost: log.gas_cost,
        storage_change: None,
        status: log.error.as_ref().map(|_| InstructionResult::Revert),
        immediate_bytes: None,
        decoded: trace_printer.then(|| {
            Box::new(DecodedTraceStep::Line(format!(
                "pc={} op={} gas={} gasCost={}",
                log.pc,
                log.opcode(),
                log.gas,
                log.gas_cost
            )))
        }),
    }
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if !warnings.iter().any(|existing| existing == &warning) {
        warnings.push(warning);
    }
}

fn parse_call_kind(kind: &str) -> CallKind {
    match kind.to_ascii_uppercase().as_str() {
        "STATICCALL" => CallKind::StaticCall,
        "CALLCODE" => CallKind::CallCode,
        "DELEGATECALL" => CallKind::DelegateCall,
        "AUTHCALL" => CallKind::AuthCall,
        "CREATE" => CallKind::Create,
        "CREATE2" => CallKind::Create2,
        _ => CallKind::Call,
    }
}

fn storage_address(node: &CallTraceNode) -> Address {
    if node.trace.kind.is_delegate() { node.trace.caller } else { node.trace.address }
}

fn opcode_from_name(name: &str) -> Option<OpCode> {
    if let Some(rest) = name.strip_prefix("PUSH") {
        let n: u8 = rest.parse().ok()?;
        return match n {
            0 => OpCode::new(opcode::PUSH0),
            1..=32 => OpCode::new(opcode::PUSH1 + n - 1),
            _ => None,
        };
    }
    if let Some(rest) = name.strip_prefix("DUP") {
        let n: u8 = rest.parse().ok()?;
        return (1..=16).contains(&n).then(|| OpCode::new(opcode::DUP1 + n - 1)).flatten();
    }
    if let Some(rest) = name.strip_prefix("SWAP") {
        let n: u8 = rest.parse().ok()?;
        return (1..=16).contains(&n).then(|| OpCode::new(opcode::SWAP1 + n - 1)).flatten();
    }
    if let Some(rest) = name.strip_prefix("LOG") {
        let n: u8 = rest.parse().ok()?;
        return (0..=4).contains(&n).then(|| OpCode::new(opcode::LOG0 + n)).flatten();
    }

    let raw = match name {
        "STOP" => opcode::STOP,
        "ADD" => opcode::ADD,
        "MUL" => opcode::MUL,
        "SUB" => opcode::SUB,
        "DIV" => opcode::DIV,
        "SDIV" => opcode::SDIV,
        "MOD" => opcode::MOD,
        "SMOD" => opcode::SMOD,
        "ADDMOD" => opcode::ADDMOD,
        "MULMOD" => opcode::MULMOD,
        "EXP" => opcode::EXP,
        "SIGNEXTEND" => opcode::SIGNEXTEND,
        "LT" => opcode::LT,
        "GT" => opcode::GT,
        "SLT" => opcode::SLT,
        "SGT" => opcode::SGT,
        "EQ" => opcode::EQ,
        "ISZERO" => opcode::ISZERO,
        "AND" => opcode::AND,
        "OR" => opcode::OR,
        "XOR" => opcode::XOR,
        "NOT" => opcode::NOT,
        "BYTE" => opcode::BYTE,
        "SHL" => opcode::SHL,
        "SHR" => opcode::SHR,
        "SAR" => opcode::SAR,
        "KECCAK256" | "SHA3" => opcode::KECCAK256,
        "ADDRESS" => opcode::ADDRESS,
        "BALANCE" => opcode::BALANCE,
        "ORIGIN" => opcode::ORIGIN,
        "CALLER" => opcode::CALLER,
        "CALLVALUE" => opcode::CALLVALUE,
        "CALLDATALOAD" => opcode::CALLDATALOAD,
        "CALLDATASIZE" => opcode::CALLDATASIZE,
        "CALLDATACOPY" => opcode::CALLDATACOPY,
        "CODESIZE" => opcode::CODESIZE,
        "CODECOPY" => opcode::CODECOPY,
        "GASPRICE" => opcode::GASPRICE,
        "EXTCODESIZE" => opcode::EXTCODESIZE,
        "EXTCODECOPY" => opcode::EXTCODECOPY,
        "RETURNDATASIZE" => opcode::RETURNDATASIZE,
        "RETURNDATACOPY" => opcode::RETURNDATACOPY,
        "EXTCODEHASH" => opcode::EXTCODEHASH,
        "BLOCKHASH" => opcode::BLOCKHASH,
        "COINBASE" => opcode::COINBASE,
        "TIMESTAMP" => opcode::TIMESTAMP,
        "NUMBER" => opcode::NUMBER,
        "PREVRANDAO" | "DIFFICULTY" => opcode::DIFFICULTY,
        "GASLIMIT" => opcode::GASLIMIT,
        "CHAINID" => opcode::CHAINID,
        "SELFBALANCE" => opcode::SELFBALANCE,
        "BASEFEE" => opcode::BASEFEE,
        "BLOBHASH" => opcode::BLOBHASH,
        "BLOBBASEFEE" => opcode::BLOBBASEFEE,
        "POP" => opcode::POP,
        "MLOAD" => opcode::MLOAD,
        "MSTORE" => opcode::MSTORE,
        "MSTORE8" => opcode::MSTORE8,
        "SLOAD" => opcode::SLOAD,
        "SSTORE" => opcode::SSTORE,
        "JUMP" => opcode::JUMP,
        "JUMPI" => opcode::JUMPI,
        "PC" => opcode::PC,
        "MSIZE" => opcode::MSIZE,
        "GAS" => opcode::GAS,
        "JUMPDEST" => opcode::JUMPDEST,
        "TLOAD" => opcode::TLOAD,
        "TSTORE" => opcode::TSTORE,
        "MCOPY" => opcode::MCOPY,
        "CREATE" => opcode::CREATE,
        "CALL" => opcode::CALL,
        "CALLCODE" => opcode::CALLCODE,
        "RETURN" => opcode::RETURN,
        "DELEGATECALL" => opcode::DELEGATECALL,
        "CREATE2" => opcode::CREATE2,
        "STATICCALL" => opcode::STATICCALL,
        "REVERT" => opcode::REVERT,
        "INVALID" => opcode::INVALID,
        "SELFDESTRUCT" => opcode::SELFDESTRUCT,
        _ => return None,
    };
    OpCode::new(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};
    use revm_inspectors::tracing::types::DecodedInternalCall;
    use std::borrow::Cow;

    #[test]
    fn converts_call_frame_to_arena() {
        let child = CallFrame {
            typ: "STATICCALL".to_string(),
            from: address!("0000000000000000000000000000000000000002"),
            to: Some(address!("0000000000000000000000000000000000000003")),
            input: bytes!("12345678"),
            gas_used: U256::from(7),
            ..Default::default()
        };
        let root = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000001"),
            to: Some(address!("0000000000000000000000000000000000000002")),
            input: bytes!("abcdef01"),
            gas_used: U256::from(11),
            calls: vec![child],
            ..Default::default()
        };

        let converted = build_rpc_trace_arena(&root, &DefaultFrame::default(), false);
        let nodes = converted.arena.nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].children, vec![1]);
        assert_eq!(nodes[1].trace.kind, CallKind::StaticCall);
    }

    #[test]
    fn parses_dynamic_opcode_names() {
        assert_eq!(opcode_from_name("PUSH0"), Some(OpCode::PUSH0));
        assert_eq!(opcode_from_name("PUSH32"), Some(OpCode::PUSH32));
        assert_eq!(opcode_from_name("DUP16"), Some(OpCode::DUP16));
        assert_eq!(opcode_from_name("SWAP16"), Some(OpCode::SWAP16));
        assert_eq!(opcode_from_name("LOG4"), Some(OpCode::LOG4));
    }

    #[test]
    fn parses_struct_logs_into_steps_and_json() {
        let root = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000001"),
            to: Some(address!("0000000000000000000000000000000000000002")),
            gas_used: U256::from(3),
            ..Default::default()
        };
        let frame = DefaultFrame {
            gas: 3,
            struct_logs: vec![
                StructLog {
                    pc: 42,
                    op: Cow::Borrowed("SLOAD"),
                    gas: 100,
                    gas_cost: 2100,
                    depth: 1,
                    stack: Some(vec![U256::from(7)]),
                    ..Default::default()
                },
                StructLog {
                    pc: 43,
                    op: Cow::Borrowed("JUMPDEST"),
                    gas: 80,
                    gas_cost: 1,
                    depth: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let converted = build_rpc_trace_arena(&root, &frame, true);
        assert!(converted.warnings.is_empty());
        assert_eq!(converted.arena.nodes()[0].trace.steps.len(), 2);
        assert_eq!(converted.arena.nodes()[0].trace.steps[0].op, OpCode::SLOAD);
        assert_eq!(converted.arena.nodes()[0].trace.steps[0].gas_used, 0);
        assert_eq!(converted.arena.nodes()[0].trace.steps[1].gas_used, 20);

        let json = serde_json::to_value(json_trace_from_arena(&converted.arena.arena))
            .expect("trace json serializes");
        assert_eq!(json["rootCallId"], 0);
        assert_eq!(json["calls"][0]["gasUsed"], 3);
    }

    #[test]
    fn finalizes_root_gas_from_receipt() {
        let root = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000001"),
            to: Some(address!("0000000000000000000000000000000000000002")),
            gas_used: U256::from(11),
            ..Default::default()
        };

        let mut converted = build_rpc_trace_arena(&root, &DefaultFrame::default(), false);
        let mut warnings = converted.warnings.clone();
        finalize_rpc_trace_arena(&mut converted.arena.arena, 7, &mut warnings);

        assert_eq!(converted.arena.nodes()[0].trace.gas_used, 7);
        assert!(warnings.iter().any(|warning| {
            warning.contains("root callTracer gasUsed (11) differs from receipt gasUsed (7)")
        }));
    }

    #[test]
    fn warns_when_internal_frame_exceeds_enclosing_call_gas() {
        let root = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000001"),
            to: Some(address!("0000000000000000000000000000000000000002")),
            gas_used: U256::from(5),
            ..Default::default()
        };
        let frame = DefaultFrame {
            struct_logs: vec![
                StructLog {
                    pc: 1,
                    op: Cow::Borrowed("PUSH1"),
                    gas: 100,
                    gas_cost: 3,
                    depth: 1,
                    ..Default::default()
                },
                StructLog {
                    pc: 2,
                    op: Cow::Borrowed("STOP"),
                    gas: 80,
                    gas_cost: 0,
                    depth: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let mut converted = build_rpc_trace_arena(&root, &frame, false);
        let node = &mut converted.arena.nodes_mut()[0];
        node.trace.steps[0].decoded = Some(Box::new(DecodedTraceStep::InternalCall(
            DecodedInternalCall { func_name: "foo".to_string(), args: None, return_data: None },
            1,
        )));

        let mut warnings = converted.warnings.clone();
        finalize_rpc_trace_arena(&mut converted.arena.arena, 5, &mut warnings);

        assert!(warnings.iter().any(|warning| {
            warning.contains("internal frame 'foo' gasUsed (20) exceeds enclosing call gasUsed (5)")
        }));
    }

    #[test]
    fn grafts_local_steps_onto_remote_call_tree() {
        let child_a = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000002"),
            to: Some(address!("0000000000000000000000000000000000000003")),
            input: bytes!("aaaaaaaa"),
            gas_used: U256::from(7),
            ..Default::default()
        };
        let child_b = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000002"),
            to: Some(address!("0000000000000000000000000000000000000004")),
            input: bytes!("bbbbbbbb"),
            gas_used: U256::from(5),
            ..Default::default()
        };
        let root = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000001"),
            to: Some(address!("0000000000000000000000000000000000000002")),
            input: bytes!("abcdef01"),
            gas_used: U256::from(11),
            calls: vec![child_a.clone(), child_b.clone()],
            ..Default::default()
        };

        let mut local = build_rpc_trace_arena(&root, &DefaultFrame::default(), false).arena.arena;
        local.nodes_mut()[0].children.swap(0, 1);
        local.nodes_mut()[0].trace.steps.push(CallTraceStep {
            pc: 1,
            op: OpCode::JUMP,
            stack: None,
            push_stack: None,
            memory: None,
            returndata: Bytes::new(),
            gas_remaining: 0,
            gas_refund_counter: 0,
            gas_used: 3,
            gas_cost: 0,
            storage_change: None,
            status: None,
            immediate_bytes: None,
            decoded: None,
        });
        local.nodes_mut()[0].ordering =
            vec![TraceMemberOrder::Step(0), TraceMemberOrder::Call(0), TraceMemberOrder::Call(1)];

        let merged = graft_local_replay_onto_call_tracer(&root, &local).expect("root matches");
        let root_node = &merged.arena.nodes()[0];
        assert_eq!(root_node.children, vec![2, 1]);
        assert_eq!(root_node.trace.steps.len(), 1);
        assert_eq!(root_node.ordering[0], TraceMemberOrder::Step(0));
    }

    #[test]
    fn rejects_graft_when_root_mismatches() {
        let remote = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000001"),
            to: Some(address!("0000000000000000000000000000000000000002")),
            input: bytes!("abcdef01"),
            ..Default::default()
        };
        let local_root = CallFrame {
            typ: "CALL".to_string(),
            from: address!("0000000000000000000000000000000000000001"),
            to: Some(address!("0000000000000000000000000000000000000009")),
            input: bytes!("abcdef01"),
            ..Default::default()
        };
        let local = build_rpc_trace_arena(&local_root, &DefaultFrame::default(), false).arena.arena;

        assert!(graft_local_replay_onto_call_tracer(&remote, &local).is_none());
    }
}
