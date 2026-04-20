use std::str::FromStr;

use alloy_chains::Chain;
use alloy_primitives::{Address, B256, Bytes, Selector, keccak256, map::HashMap};
use foundry_cli::utils::{TraceResult, print_traces};
use foundry_common::{ContractsByArtifact, compile::ProjectCompiler, shell};
use foundry_config::Config;
use foundry_debugger::Debugger;
use foundry_evm::traces::{
    CallTraceDecoder, CallTraceDecoderBuilder, DebugTraceIdentifier,
    debug::ContractSources,
    identifier::{SignaturesIdentifier, TraceIdentifiers},
};

pub(crate) struct PreparedTraceDecoder {
    pub decoder: CallTraceDecoder,
    pub sources: ContractSources,
}

fn build_selector_candidates(contracts: &ContractsByArtifact) -> HashMap<Selector, Vec<String>> {
    let mut selector_candidates = HashMap::default();
    for (id, contract) in contracts.iter() {
        for function in contract.abi.functions() {
            selector_candidates
                .entry(function.selector())
                .or_insert_with(Vec::new)
                .push(id.name.clone());
        }
    }
    for candidates in selector_candidates.values_mut() {
        candidates.sort();
        candidates.dedup();
    }
    selector_candidates
}

fn build_exact_runtime_candidates(
    contracts: &ContractsByArtifact,
    contracts_bytecode: &HashMap<Address, Bytes>,
) -> HashMap<Address, Vec<String>> {
    let mut local_runtime_hashes: HashMap<B256, Vec<String>> = HashMap::default();
    for (id, contract) in contracts.iter() {
        let Some(runtime) = contract.deployed_bytecode() else { continue };
        local_runtime_hashes
            .entry(keccak256(runtime))
            .or_insert_with(Vec::new)
            .push(id.name.clone());
    }
    for candidates in local_runtime_hashes.values_mut() {
        candidates.sort();
        candidates.dedup();
    }

    let mut exact_runtime_candidates = HashMap::default();
    for (address, runtime) in contracts_bytecode {
        if runtime.is_empty() {
            continue;
        }
        if let Some(candidates) = local_runtime_hashes.get(&keccak256(runtime)) {
            exact_runtime_candidates.insert(*address, candidates.clone());
        }
    }
    exact_runtime_candidates
}

/// labels the traces, conditionally prints them or opens the debugger
#[expect(clippy::too_many_arguments)]
pub(crate) async fn handle_traces(
    mut result: TraceResult,
    config: &Config,
    chain: Chain,
    contracts_bytecode: &HashMap<Address, Bytes>,
    labels: Vec<String>,
    with_local_artifacts: bool,
    debug: bool,
    decode_internal: bool,
    disable_label: bool,
    trace_depth: Option<usize>,
) -> eyre::Result<()> {
    let PreparedTraceDecoder { decoder, sources } = prepare_trace_decoder(
        &result,
        config,
        chain,
        contracts_bytecode,
        labels,
        with_local_artifacts,
        debug || decode_internal,
        disable_label,
    )
    .await?;

    if debug {
        let mut debugger = Debugger::builder()
            .traces(result.traces.expect("missing traces"))
            .decoder(&decoder)
            .sources(sources)
            .build();
        debugger.try_run_tui()?;
        return Ok(());
    }

    print_traces(
        &mut result,
        &decoder,
        shell::verbosity() > 0,
        shell::verbosity() > 4,
        trace_depth,
    )
    .await?;

    Ok(())
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn prepare_trace_decoder(
    result: &TraceResult,
    config: &Config,
    chain: Chain,
    contracts_bytecode: &HashMap<Address, Bytes>,
    labels: Vec<String>,
    with_local_artifacts: bool,
    decode_internal: bool,
    disable_label: bool,
) -> eyre::Result<PreparedTraceDecoder> {
    let (known_contracts, selector_candidates, exact_runtime_candidates, mut sources) =
        if with_local_artifacts {
            if !shell::is_json() {
                let _ = sh_println!("Compiling project to generate artifacts");
            }
            let project = config.project()?;
            let compiler = ProjectCompiler::new();
            let output = compiler.compile(&project)?;
            let known_contracts = ContractsByArtifact::new(
                output.artifact_ids().map(|(id, artifact)| (id, artifact.clone().into())),
            );
            (
                Some(known_contracts.clone()),
                build_selector_candidates(&known_contracts),
                build_exact_runtime_candidates(&known_contracts, contracts_bytecode),
                ContractSources::from_project_output(&output, project.root(), None)?,
            )
        } else {
            (None, HashMap::default(), HashMap::default(), ContractSources::default())
        };

    let labels = labels.iter().filter_map(|label_str| {
        let mut iter = label_str.split(':');

        if let Some(addr) = iter.next()
            && let (Ok(address), Some(label)) = (Address::from_str(addr), iter.next())
        {
            return Some((address, label.to_string()));
        }
        None
    });
    let config_labels = config.labels.clone().into_iter();

    let mut builder = CallTraceDecoderBuilder::new()
        .with_labels(labels.chain(config_labels))
        .with_signature_identifier(SignaturesIdentifier::from_config(config)?)
        .with_label_disabled(disable_label)
        .with_chain_id(Some(chain.id()));
    let mut identifier = TraceIdentifiers::new().with_external(config, Some(chain))?;
    if let Some(contracts) = &known_contracts {
        builder = builder.with_known_contracts(contracts);
        identifier = identifier.with_local_and_bytecodes(contracts, contracts_bytecode);
    }

    let mut decoder = builder.build();

    for (_, trace) in result.traces.as_deref().unwrap_or_default() {
        decoder.identify(trace, &mut identifier);
    }

    if decode_internal {
        if let Some(ref etherscan_identifier) = identifier.external {
            sources.merge(etherscan_identifier.get_compiled_contracts().await?);
        }

        decoder.debug_identifier = Some(
            DebugTraceIdentifier::new(sources.clone())
                .with_selector_candidates(selector_candidates)
                .with_exact_runtime_candidates(exact_runtime_candidates),
        );
    }

    Ok(PreparedTraceDecoder { decoder, sources })
}
