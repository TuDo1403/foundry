mod sources;
use crate::CallTraceNode;
use alloy_dyn_abi::{
    DynSolType, DynSolValue, Specifier,
    parser::{ParameterSpecifier, Parameters, Storage},
};
use alloy_primitives::{Address, Selector, U256, map::HashMap};
use foundry_common::fmt::format_token;
use foundry_compilers::artifacts::sourcemap::{Jump, SourceElement};
use revm::bytecode::opcode::OpCode;
use revm_inspectors::tracing::types::{CallTraceStep, DecodedInternalCall, DecodedTraceStep};
pub use sources::{ArtifactData, ContractSources, SourceData};

#[derive(Clone, Debug)]
pub struct DebugTraceIdentifier {
    /// Source map of contract sources
    contracts_sources: ContractSources,
    /// Selector -> candidate contract names from the local artifacts.
    selector_candidates: HashMap<Selector, Vec<String>>,
    /// Exact runtime-bytecode matches for traced addresses.
    exact_runtime_candidates: HashMap<Address, Vec<String>>,
}

impl DebugTraceIdentifier {
    pub fn new(contracts_sources: ContractSources) -> Self {
        Self {
            contracts_sources,
            selector_candidates: HashMap::default(),
            exact_runtime_candidates: HashMap::default(),
        }
    }

    pub fn with_selector_candidates(
        mut self,
        selector_candidates: HashMap<Selector, Vec<String>>,
    ) -> Self {
        self.selector_candidates = selector_candidates;
        self
    }

    pub fn with_exact_runtime_candidates(
        mut self,
        exact_runtime_candidates: HashMap<Address, Vec<String>>,
    ) -> Self {
        self.exact_runtime_candidates = exact_runtime_candidates;
        self
    }

    pub fn has_exact_runtime_match(&self, address: Address) -> bool {
        self.exact_runtime_candidates.contains_key(&address)
    }

    pub fn preferred_contract_name(
        &self,
        node: &CallTraceNode,
        identified_contract_name: Option<&str>,
    ) -> Option<String> {
        self.exact_runtime_contract_name(node, identified_contract_name)
            .or_else(|| identified_contract_name.map(str::to_string))
            .or_else(|| self.infer_contract_name(node))
    }

    /// Identifies internal function invocations in a given [CallTraceNode].
    ///
    /// Accepts the node itself and identified name of the contract which node corresponds to.
    pub fn identify_node_steps(&self, node: &mut CallTraceNode, contract_name: &str) {
        DebugStepsWalker::new(node, &self.contracts_sources, contract_name).walk();
    }

    fn exact_runtime_contract_name(
        &self,
        node: &CallTraceNode,
        identified_contract_name: Option<&str>,
    ) -> Option<String> {
        let candidates = self.exact_runtime_candidates.get(&node.trace.address)?;

        if let Some(identified_contract_name) = identified_contract_name
            && candidates.iter().any(|candidate| candidate == identified_contract_name)
        {
            return Some(identified_contract_name.to_string());
        }

        if candidates.len() == 1 {
            return Some(candidates[0].clone());
        }

        self.infer_contract_name_from_candidates(node, candidates.iter().map(String::as_str))
    }

    /// Best-effort inference for frames whose runtime bytecode did not match a local artifact.
    ///
    /// This samples program counters from the frame and looks for the contract whose source maps
    /// cover the most steps, biasing toward contracts that also contain the externally-decoded
    /// function name. This lets `run --trace` recover inherited/library internals even when the
    /// deployed bytecode is not an exact local match.
    pub fn infer_contract_name(&self, node: &CallTraceNode) -> Option<String> {
        self.infer_contract_name_from_candidates(
            node,
            self.contracts_sources.entries().map(|(contract_name, _, _)| contract_name),
        )
    }

    fn infer_contract_name_from_candidates<'a>(
        &self,
        node: &CallTraceNode,
        contract_names: impl IntoIterator<Item = &'a str>,
    ) -> Option<String> {
        if node.trace.steps.is_empty() {
            return None;
        }

        let function_name = external_function_name(node);
        let selector_candidates =
            node.selector().and_then(|selector| self.selector_candidates.get(&selector));
        let sampled_pcs = sample_step_pcs(&node.trace.steps, 16);
        let init_code = node.trace.kind.is_any_create();
        let mut best_match: Option<(usize, usize, &str)> = None;
        let contract_names: Vec<&str> = contract_names.into_iter().collect();

        for (contract_name, _, source) in self.contracts_sources.entries() {
            if !contract_names.is_empty() && !contract_names.contains(&contract_name) {
                continue;
            }
            if let Some(selector_candidates) = selector_candidates
                && !selector_candidates.iter().any(|candidate| candidate == contract_name)
            {
                continue;
            }
            if is_non_runtime_source(&source.path) {
                continue;
            }

            let mut mapped_steps = 0usize;
            let mut function_hits = 0usize;

            for pc in &sampled_pcs {
                let Some((source_element, mapped_source)) = self
                    .contracts_sources
                    .find_source_mapping(contract_name, *pc as u32, init_code)
                else {
                    continue;
                };
                mapped_steps += 1;

                if let Some(function_name) = function_name
                    && source_span(
                        &mapped_source.source,
                        source_element.offset() as usize,
                        source_element.length() as usize,
                    )
                    .is_some_and(|(source_part, _)| source_part.contains(function_name))
                {
                    function_hits += 1;
                }
            }

            if mapped_steps == 0 {
                continue;
            }

            let current = (function_hits, mapped_steps, contract_name);
            if best_match.is_none_or(|best| current > best) {
                best_match = Some(current);
            }
        }

        best_match.map(|(_, _, contract_name)| contract_name.to_string())
    }
}

/// Walks through the [CallTraceStep]s attempting to match JUMPs to internal functions.
///
/// This is done by looking up jump kinds in the source maps. The structure of internal function
/// call always looks like this:
///     - JUMP
///     - JUMPDEST
///     ... function steps ...
///     - JUMP
///     - JUMPDEST
///
/// The assumption we rely on is that first JUMP into function will be marked as [Jump::In] in
/// source map, and second JUMP out of the function will be marked as [Jump::Out].
///
/// Also, we rely on JUMPDEST after first JUMP pointing to the source location of the body of
/// function which was entered. We pass this source part to [parse_function_from_loc] to extract the
/// function name.
///
/// When we find a [Jump::In] and identify the function name, we push it to the stack.
///
/// When we find a [Jump::Out] we try to find a matching [Jump::In] in the stack. A match is found
/// when source location of the JUMP-in matches the source location of final JUMPDEST (this would be
/// the location of the function invocation), or when source location of first JUMODEST matches the
/// source location of the JUMP-out (this would be the location of function body).
///
/// When a match is found, all items which were pushed after the matched function are removed. There
/// is a lot of such items due to source maps getting malformed during optimization.
struct DebugStepsWalker<'a> {
    node: &'a mut CallTraceNode,
    current_step: usize,
    stack: Vec<(String, usize)>,
    sources: &'a ContractSources,
    contract_name: &'a str,
}

impl<'a> DebugStepsWalker<'a> {
    pub const fn new(
        node: &'a mut CallTraceNode,
        sources: &'a ContractSources,
        contract_name: &'a str,
    ) -> Self {
        Self { node, current_step: 0, stack: Vec::new(), sources, contract_name }
    }

    fn current_step(&self) -> &CallTraceStep {
        &self.node.trace.steps[self.current_step]
    }

    fn src_map(&self, step: usize) -> Option<(SourceElement, &SourceData)> {
        self.sources.find_source_mapping(
            self.contract_name,
            self.node.trace.steps[step].pc as u32,
            self.node.trace.kind.is_any_create(),
        )
    }

    fn prev_src_map(&self) -> Option<(SourceElement, &SourceData)> {
        if self.current_step == 0 {
            return None;
        }

        self.src_map(self.current_step - 1)
    }

    fn current_src_map(&self) -> Option<(SourceElement, &SourceData)> {
        self.src_map(self.current_step)
    }

    fn is_same_loc(&self, step: usize, other: usize) -> bool {
        let Some((loc, _)) = self.src_map(step) else {
            return false;
        };
        let Some((other_loc, _)) = self.src_map(other) else {
            return false;
        };

        loc.offset() == other_loc.offset()
            && loc.length() == other_loc.length()
            && loc.index() == other_loc.index()
    }

    /// Invoked when current step is a JUMPDEST preceded by a JUMP marked as [Jump::In].
    fn jump_in(&mut self) {
        // This usually means that this is a jump into the external function which is an
        // entrypoint for the current frame. We don't want to include this to avoid
        // duplicating traces.
        if self.is_same_loc(self.current_step, self.current_step - 1) {
            return;
        }

        let Some((source_element, source)) = self.current_src_map() else {
            return;
        };

        if let Some(name) = parse_function_from_loc(source, &source_element) {
            self.stack.push((name, self.current_step - 1));
        }
    }

    /// Invoked when current step is a JUMPDEST preceded by a JUMP marked as [Jump::Out].
    fn jump_out(&mut self) {
        let Some((i, _)) = self.stack.iter().enumerate().rfind(|(_, (_, step_idx))| {
            self.is_same_loc(*step_idx, self.current_step)
                || self.is_same_loc(step_idx + 1, self.current_step - 1)
        }) else {
            return;
        };
        // We've found a match, remove all records between start and end, those
        // are considered invalid.
        let (func_name, start_idx) = self.stack.split_off(i).swap_remove(0);

        // Try to decode function inputs and outputs from the stack and memory.
        let (inputs, outputs) = self
            .src_map(start_idx + 1)
            .and_then(|(source_element, source)| {
                let start = source_element.offset() as usize;
                let (fn_definition, _) =
                    source_span(&source.source, start, source_element.length() as usize)?;
                let fn_definition = fn_definition.replace('\n', "");
                let (inputs, outputs) = parse_types(&fn_definition);

                Some((
                    inputs.and_then(|t| {
                        try_decode_args_from_step(&t, &self.node.trace.steps[start_idx + 1])
                    }),
                    outputs.and_then(|t| try_decode_args_from_step(&t, self.current_step())),
                ))
            })
            .unwrap_or_default();

        self.node.trace.steps[start_idx].decoded = Some(Box::new(DecodedTraceStep::InternalCall(
            DecodedInternalCall { func_name, args: inputs, return_data: outputs },
            self.current_step,
        )));
    }

    fn process(&mut self) {
        // We are only interested in JUMPs.
        if self.current_step().op != OpCode::JUMP && self.current_step().op != OpCode::JUMPDEST {
            return;
        }

        let Some((prev_source_element, _)) = self.prev_src_map() else {
            return;
        };

        match prev_source_element.jump() {
            Jump::In => self.jump_in(),
            Jump::Out => self.jump_out(),
            _ => {}
        };
    }

    fn step(&mut self) {
        self.process();
        self.current_step += 1;
    }

    pub fn walk(mut self) {
        while self.current_step < self.node.trace.steps.len() {
            self.step();
        }
    }
}

/// Tries to parse the function name from the source code and detect the contract name which
/// contains the given function.
///
/// Returns string in the format `Contract::function`.
fn parse_function_from_loc(source: &SourceData, loc: &SourceElement) -> Option<String> {
    let start = loc.offset() as usize;
    let (source_part, end) = source_span(&source.source, start, loc.length() as usize)?;

    if !source_part.starts_with("function") {
        return None;
    }
    let function_name = source_part.split_once("function")?.1.split('(').next()?.trim();
    let contract_name = source.find_contract_name(start, end)?;

    Some(format!("{contract_name}::{function_name}"))
}

fn external_function_name(node: &CallTraceNode) -> Option<&str> {
    let signature = node.trace.decoded.as_deref()?.call_data.as_ref()?.signature.as_str();
    let name = signature.split_once('(').map(|(name, _)| name).unwrap_or(signature);
    if name.is_empty() || name == "fallback" || name.starts_with("0x") {
        return None;
    }
    Some(name)
}

fn sample_step_pcs(steps: &[CallTraceStep], max_samples: usize) -> Vec<usize> {
    if steps.is_empty() {
        return Vec::new();
    }
    if steps.len() <= max_samples {
        return steps.iter().map(|step| step.pc).collect();
    }

    let last = steps.len() - 1;
    let mut pcs = Vec::with_capacity(max_samples);
    for idx in 0..max_samples {
        let step_idx = idx * last / (max_samples - 1);
        let pc = steps[step_idx].pc;
        if pcs.last().copied() != Some(pc) {
            pcs.push(pc);
        }
    }
    pcs
}

fn is_non_runtime_source(path: &std::path::Path) -> bool {
    path.components().any(|component| {
        let component = component.as_os_str().to_string_lossy();
        matches!(
            component.as_ref(),
            "test" | "tests" | "script" | "scripts" | "benchmark" | "benchmarks"
        )
    })
}

fn source_span(source: &str, start: usize, len: usize) -> Option<(&str, usize)> {
    let end = start.checked_add(len)?;

    Some((source.get(start..end)?, end))
}

/// Parses function input and output types into [Parameters].
fn parse_types(source: &str) -> (Option<Parameters<'_>>, Option<Parameters<'_>>) {
    let inputs = source.find('(').and_then(|params_start| {
        let params_end = params_start + source[params_start..].find(')')?;
        Parameters::parse(&source[params_start..params_end + 1]).ok()
    });
    let outputs = source.find("returns").and_then(|returns_start| {
        let return_params_start = returns_start + source[returns_start..].find('(')?;
        let return_params_end = return_params_start + source[return_params_start..].find(')')?;
        Parameters::parse(&source[return_params_start..return_params_end + 1]).ok()
    });

    (inputs, outputs)
}

/// Given [Parameters] and [CallTraceStep], tries to decode parameters by using stack and memory.
fn try_decode_args_from_step(args: &Parameters<'_>, step: &CallTraceStep) -> Option<Vec<String>> {
    let params = &args.params;

    if params.is_empty() {
        return Some(vec![]);
    }

    let stack = step.stack.as_ref()?;

    if stack.len() < params.len() {
        return None;
    }

    let inputs = &stack[stack.len() - params.len()..];

    let decoded = inputs
        .iter()
        .zip(params.iter())
        .map(|(input, param)| {
            if param.storage.is_none() && is_user_defined_type(param.ty.span()) {
                return format_unresolved_arg(param, input);
            }

            param
                .resolve()
                .ok()
                .and_then(|type_| {
                    match (type_, param.storage) {
                        // HACK: alloy parser treats user-defined types as uint8: https://github.com/alloy-rs/core/pull/386
                        //
                        // filter out `uint8` params which are marked as storage or memory as this
                        // is not possible in Solidity and means that type is user-defined
                        (DynSolType::Uint(8), Some(Storage::Memory | Storage::Storage)) => None,
                        (type_, Some(Storage::Memory)) => decode_from_memory(
                            &type_,
                            step.memory.as_ref()?.as_bytes(),
                            input.try_into().ok()?,
                        ),
                        // Read other types from stack
                        (type_, _) => type_.abi_decode(&input.to_be_bytes::<32>()).ok(),
                    }
                })
                .as_ref()
                .map(format_token)
                .unwrap_or_else(|| format_unresolved_arg(param, input))
        })
        .collect();

    Some(decoded)
}

fn format_unresolved_arg(param: &ParameterSpecifier<'_>, input: &U256) -> String {
    let raw = format_stack_word(input);
    let ty = param.ty.span();

    match param.storage {
        Some(Storage::Storage) => format!("{ty} storage@{raw}"),
        Some(Storage::Memory) => format!("{ty} memory@{raw}"),
        Some(Storage::Calldata) => format!("{ty} calldata@{raw}"),
        None if is_user_defined_type(ty) || param.resolve().is_err() => format!("{ty}.wrap({raw})"),
        None => raw,
    }
}

fn format_stack_word(input: &U256) -> String {
    format!("0x{input:064x}")
}

fn is_user_defined_type(ty: &str) -> bool {
    let root = ty.split('[').next().unwrap_or(ty);
    if root.starts_with('(') {
        return false;
    }

    if matches!(root, "address" | "bool" | "string" | "bytes" | "function" | "uint" | "int") {
        return false;
    }

    if let Some(size) = root.strip_prefix("bytes") {
        return size.parse::<u16>().is_err();
    }
    let numeric_size = root.strip_prefix("uint").or_else(|| root.strip_prefix("int"));
    if let Some(size) = numeric_size {
        return size.parse::<u16>().is_err();
    }

    true
}

/// Decodes given [DynSolType] from memory.
fn decode_from_memory(ty: &DynSolType, memory: &[u8], location: usize) -> Option<DynSolValue> {
    let first_word = memory.get(location..location + 32)?;

    match ty {
        // For `string` and `bytes` layout is a word with length followed by the data
        DynSolType::String | DynSolType::Bytes => {
            let length: usize = U256::from_be_slice(first_word).try_into().ok()?;
            let data = memory.get(location + 32..location + 32 + length)?;

            match ty {
                DynSolType::Bytes => Some(DynSolValue::Bytes(data.to_vec())),
                DynSolType::String => {
                    Some(DynSolValue::String(String::from_utf8_lossy(data).to_string()))
                }
                _ => unreachable!(),
            }
        }
        // Dynamic arrays are encoded as a word with length followed by words with elements
        // Fixed arrays are encoded as words with elements
        DynSolType::Array(inner) | DynSolType::FixedArray(inner, _) => {
            let (length, start) = match ty {
                DynSolType::FixedArray(_, length) => (*length, location),
                DynSolType::Array(_) => {
                    (U256::from_be_slice(first_word).try_into().ok()?, location + 32)
                }
                _ => unreachable!(),
            };
            let mut decoded = Vec::with_capacity(length);

            for i in 0..length {
                let offset = start + i * 32;
                let location = match inner.as_ref() {
                    // Arrays of variable length types are arrays of pointers to the values
                    DynSolType::String | DynSolType::Bytes | DynSolType::Array(_) => {
                        U256::from_be_slice(memory.get(offset..offset + 32)?).try_into().ok()?
                    }
                    _ => offset,
                };

                decoded.push(decode_from_memory(inner, memory, location)?);
            }

            Some(DynSolValue::Array(decoded))
        }
        _ => ty.abi_decode(first_word).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::{source_span, try_decode_args_from_step};
    use alloy_dyn_abi::parser::Parameters;
    use alloy_primitives::U256;
    use revm::bytecode::opcode::OpCode;
    use revm_inspectors::tracing::types::CallTraceStep;

    #[test]
    fn source_span_returns_none_for_invalid_ranges() {
        assert_eq!(source_span("abcdef", 2, 3), Some(("cde", 5)));
        assert_eq!(source_span("abcdef", 7, 1), None);
        assert_eq!(source_span("abcdef", usize::MAX, 1), None);
    }

    #[test]
    fn unresolved_udvt_args_fall_back_to_wrapped_stack_word() {
        let slot = U256::from_be_slice(&[0x11; 32]);
        let args = Parameters::parse("(TransientSlot.BooleanSlot slot, bool value)").unwrap();
        let step = CallTraceStep {
            stack: Some(vec![slot, U256::from(1)].into_boxed_slice()),
            ..empty_step()
        };

        let decoded = try_decode_args_from_step(&args, &step).unwrap();
        assert_eq!(
            decoded,
            vec![format!("TransientSlot.BooleanSlot.wrap(0x{:064x})", slot), "true".to_string(),]
        );
    }

    #[test]
    fn unresolved_storage_args_fall_back_to_typed_slot_pointer() {
        let slot = U256::from(0x1234);
        let args = Parameters::parse("(PerpsMarketStorage storage self, uint16 marketId)").unwrap();
        let step = CallTraceStep {
            stack: Some(vec![slot, U256::from(4)].into_boxed_slice()),
            ..empty_step()
        };

        let decoded = try_decode_args_from_step(&args, &step).unwrap();
        assert_eq!(
            decoded,
            vec![format!("PerpsMarketStorage storage@0x{:064x}", slot), "4".to_string()]
        );
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
