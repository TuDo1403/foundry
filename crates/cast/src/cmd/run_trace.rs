use super::run::{ReplayTxArgs, replay_transaction};
use crate::debug::prepare_trace_decoder;
use alloy_chains::Chain;
use alloy_network::Network;
use alloy_primitives::{Address, Bytes, TxHash, map::HashMap};
use alloy_provider::{Provider, ext::DebugApi};
use alloy_rpc_types::{
    BlockId, BlockNumberOrTag,
    trace::geth::{
        CallConfig, GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, PreStateConfig,
    },
};
use clap::Parser;
use eyre::{Context, Result};
use foundry_cli::{
    opts::RpcOpts,
    utils::{self, TraceResult, print_traces},
};
use foundry_common::{shell, stdin};
use foundry_config::Config;
use foundry_evm::traces::{
    TraceKind,
    rpc_profile::{RpcTraceProfiles, profile_arena},
    rpc_trace::{
        build_rpc_trace_arena, finalize_rpc_trace_arena, graft_local_replay_onto_call_tracer,
    },
};
use foundry_evm::{hardforks::FoundryHardfork, revm::primitives::hardfork::SpecId};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    borrow::Cow,
    fs::File,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};

/// Internal arguments for `cast run --trace`.
#[derive(Clone, Debug, Parser)]
pub struct RunTraceArgs {
    /// The transaction hash.
    ///
    /// Reads from stdin when omitted.
    pub(crate) tx_hash: Option<String>,

    /// Whether to identify internal functions in traces.
    #[arg(long)]
    pub(crate) decode_internal: bool,

    /// Defines the depth of a trace.
    #[arg(long)]
    pub(crate) trace_depth: Option<usize>,

    /// Print opcode-level lines in the trace.
    #[arg(long, short)]
    pub(crate) trace_printer: bool,

    /// Skip optional metadata lookups for faster decoded terminal output.
    ///
    /// This avoids `eth_getTransactionByHash`, `eth_getTransactionReceipt`, and
    /// `eth_getBlockByNumber` when they are not needed for rendering. JSON output, local artifact
    /// decoding, and explicit raw RPC cache paths still fetch the required metadata.
    #[arg(long)]
    pub(crate) quick: bool,

    /// Disables labels in the traces.
    #[arg(long, default_value_t = false)]
    pub(crate) disable_labels: bool,

    /// Label addresses in the trace.
    ///
    /// Example: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045:vitalik.eth
    #[arg(long, short)]
    pub(crate) label: Vec<String>,

    /// Use current project artifacts for trace decoding.
    #[arg(long, visible_alias = "la")]
    pub(crate) with_local_artifacts: bool,

    /// Print gas and storage profiler summaries.
    #[arg(long)]
    pub(crate) profile: bool,

    /// Disable storage hot-slot profiling.
    #[arg(long)]
    pub(crate) no_storage_profile: bool,

    /// Fetch pre/post storage values with prestateTracer diff mode.
    #[arg(long)]
    pub(crate) storage_values: bool,

    /// Include full memory snapshots in the opcode trace for deeper internal argument decoding.
    ///
    /// This can make debug_traceTransaction responses very large; some RPCs reject large traces.
    #[arg(long, alias = "full-memory")]
    pub(crate) enable_memory: bool,

    /// Read/write raw RPC trace responses at this path.
    #[arg(long)]
    pub(crate) raw_rpc_cache: Option<PathBuf>,

    /// Local JSON file containing the callTracer response.
    ///
    /// Accepts either the raw tracer result object or a full JSON-RPC response envelope.
    #[arg(long)]
    pub(crate) call_trace_json: Option<PathBuf>,

    /// Local JSON file containing the default struct logger response.
    ///
    /// Accepts either the raw tracer result object or a full JSON-RPC response envelope.
    #[arg(long)]
    pub(crate) struct_trace_json: Option<PathBuf>,

    /// Local JSON file containing the prestateTracer diff response.
    ///
    /// Accepts either the raw tracer result object or a full JSON-RPC response envelope.
    #[arg(long)]
    pub(crate) storage_values_json: Option<PathBuf>,

    /// Local JSON file containing `eth_getTransactionByHash` result for this tx.
    ///
    /// Accepts either the raw result object or a full JSON-RPC response envelope.
    #[arg(long)]
    pub(crate) tx_json: Option<PathBuf>,

    /// Local JSON file containing `eth_getTransactionReceipt` result for this tx.
    ///
    /// Accepts either the raw result object or a full JSON-RPC response envelope.
    #[arg(long)]
    pub(crate) receipt_json: Option<PathBuf>,

    /// Local JSON file containing `eth_getBlockByNumber(..., false)` result for this tx's block.
    ///
    /// Accepts either the raw result object or a full JSON-RPC response envelope.
    #[arg(long)]
    pub(crate) block_json: Option<PathBuf>,

    /// Disable the automatic raw RPC trace cache.
    #[arg(long)]
    pub(crate) no_rpc_trace_cache: bool,

    /// Ignore any existing raw RPC trace cache and overwrite it.
    #[arg(long)]
    pub(crate) refresh_rpc_trace_cache: bool,

    /// Allow decoded output even when local bytecode matching is incomplete.
    #[arg(long)]
    pub(crate) allow_bytecode_mismatch: bool,

    #[command(flatten)]
    pub(crate) rpc: RpcOpts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRpcTraceCache {
    chain_id: u64,
    tx: Value,
    receipt: Value,
    block: Value,
    #[serde(default)]
    call_trace: Option<GethTrace>,
    #[serde(default)]
    call_trace_warning: Option<String>,
    #[serde(default)]
    struct_trace: Option<GethTrace>,
    #[serde(default)]
    struct_trace_warning: Option<String>,
    storage_values: Option<GethTrace>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JsonFileInput<T> {
    Raw(T),
    RpcSuccess { result: T },
    RpcError { error: Value },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MetadataFetchPlan {
    tx: bool,
    receipt: bool,
    block: bool,
    automatic_cache: bool,
}

impl RunTraceArgs {
    pub async fn run(self) -> Result<()> {
        let config =
            Config::from_provider(self.rpc.clone().into_figment(self.with_local_artifacts))?
                .sanitized();
        let provider = utils::get_provider(&config)?;
        let tx_hash: TxHash =
            stdin::unwrap_line(self.tx_hash.clone())?.parse().wrap_err("invalid tx hash")?;

        let raw = self.load_or_fetch_raw_traces(&provider, tx_hash).await?;
        let mut warnings = Vec::new();
        if let Some(warning) = raw.call_trace_warning.clone() {
            warnings.push(warning);
        }
        if let Some(warning) = raw.struct_trace_warning.clone() {
            warnings.push(warning);
        }
        let refund_quotient = self.rpc_refund_quotient(&provider, &raw).await?;

        let (mut result, mut mode_warnings, contracts_bytecode) = if let (
            Some(call_trace),
            Some(struct_trace),
        ) =
            (raw.call_trace.clone(), raw.struct_trace.clone())
        {
            let call_frame = call_trace.try_into_call_frame().map_err(|_| {
                eyre::eyre!("debug_traceTransaction callTracer returned an unexpected shape")
            })?;
            let default_frame = struct_trace.try_into_default_frame().map_err(|_| {
                eyre::eyre!("debug_traceTransaction default tracer returned an unexpected shape")
            })?;

            let receipt_gas = gas_used_from_receipt(&raw.receipt).unwrap_or(default_frame.gas);
            let mut converted = build_rpc_trace_arena(
                &call_frame,
                &default_frame,
                self.trace_printer,
                refund_quotient,
            );
            let mut warnings = Vec::new();
            warnings.append(&mut converted.warnings);
            finalize_rpc_trace_arena(&mut converted.arena.arena, receipt_gas, &mut warnings);
            if !raw.receipt.is_null() && receipt_gas != default_frame.gas {
                warnings.push(format!(
                    "receipt gasUsed ({receipt_gas}) differs from structLogger gas ({})",
                    default_frame.gas
                ));
            }

            let result = TraceResult {
                success: !default_frame.failed,
                traces: Some(vec![(TraceKind::Execution, converted.arena)]),
                gas_used: receipt_gas,
            };
            let contracts_bytecode = if self.with_local_artifacts {
                fetch_contracts_bytecode(&provider, &result, block_number_from_tx(&raw.tx)).await
            } else {
                HashMap::default()
            };
            (result, warnings, contracts_bytecode)
        } else if let Some(call_trace) = raw.call_trace.clone() {
            let replay = self.replay_transaction_locally(tx_hash).await?;
            let local_execution = execution_trace(&replay.result)
                .ok_or_else(|| eyre::eyre!("local replay did not produce an execution trace"))?;
            let call_frame = call_trace.try_into_call_frame().map_err(|_| {
                eyre::eyre!("debug_traceTransaction callTracer returned an unexpected shape")
            })?;

            if let Some(mut converted) =
                graft_local_replay_onto_call_tracer(&call_frame, &local_execution.arena)
            {
                let receipt_gas = gas_used_from_receipt(&raw.receipt)
                    .unwrap_or(converted.arena.nodes()[0].trace.gas_used);
                let mut warnings = Vec::new();
                warnings.append(&mut converted.warnings);
                warnings.push(
                    "using remote callTracer as the call skeleton and local cast run replay for opcode steps".to_string(),
                );
                finalize_rpc_trace_arena(&mut converted.arena.arena, receipt_gas, &mut warnings);
                if receipt_gas != replay.result.gas_used {
                    warnings.push(format!(
                        "receipt gasUsed ({receipt_gas}) differs from local replay gas ({})",
                        replay.result.gas_used
                    ));
                }
                let success = converted.arena.nodes()[0].trace.success;
                let result = TraceResult {
                    success,
                    traces: Some(vec![(TraceKind::Execution, converted.arena)]),
                    gas_used: receipt_gas,
                };
                let contracts_bytecode = if self.with_local_artifacts {
                    replay.contracts_bytecode
                } else {
                    HashMap::default()
                };
                (result, warnings, contracts_bytecode)
            } else {
                let mut warnings = vec![
                    "callTracer could not be aligned with local replay; using pure local replay"
                        .to_string(),
                ];
                if let Some(receipt_gas) = gas_used_from_receipt(&raw.receipt)
                    && receipt_gas != replay.result.gas_used
                {
                    warnings.push(format!(
                        "receipt gasUsed ({receipt_gas}) differs from local replay gas ({})",
                        replay.result.gas_used
                    ));
                }
                let contracts_bytecode = if self.with_local_artifacts {
                    replay.contracts_bytecode
                } else {
                    HashMap::default()
                };
                (replay.result, warnings, contracts_bytecode)
            }
        } else {
            let replay = self.replay_transaction_locally(tx_hash).await?;
            let mut warnings =
                vec!["callTracer was unavailable; using pure local cast run replay".to_string()];
            if let Some(receipt_gas) = gas_used_from_receipt(&raw.receipt)
                && receipt_gas != replay.result.gas_used
            {
                warnings.push(format!(
                    "receipt gasUsed ({receipt_gas}) differs from local replay gas ({})",
                    replay.result.gas_used
                ));
            }
            let contracts_bytecode = if self.with_local_artifacts {
                replay.contracts_bytecode
            } else {
                HashMap::default()
            };
            (replay.result, warnings, contracts_bytecode)
        };
        warnings.append(&mut mode_warnings);

        if self.allow_bytecode_mismatch {
            warnings.push(
                "--allow-bytecode-mismatch is accepted for compatibility; unmatched local bytecode is already decoded conservatively".to_string(),
            );
        }
        if self.storage_values && raw.storage_values.is_none() {
            warnings.push(
                "--storage-values was requested but no prestateTracer response was available"
                    .to_string(),
            );
        }
        if self.quick && raw.receipt.is_null() {
            warnings.push(
                "--quick skips receipt lookup; gasUsed may differ from the mined receipt"
                    .to_string(),
            );
        }

        let prepared = prepare_trace_decoder(
            &result,
            &config,
            Chain::from(raw.chain_id),
            &contracts_bytecode,
            self.label,
            self.with_local_artifacts,
            self.decode_internal,
            self.disable_labels,
        )
        .await?;

        warnings.sort();
        warnings.dedup();

        print_traces(
            &mut result,
            &prepared.decoder,
            shell::verbosity() > 0,
            shell::verbosity() > 4,
            self.trace_depth,
        )
        .await?;

        if shell::is_json() {
            for warning in warnings {
                sh_warn!("{warning}")?;
            }
            return Ok(());
        }

        if self.profile {
            let arena = &result.traces.as_ref().unwrap()[0].1.arena;
            let profiles = profile_arena(arena, !self.no_storage_profile);
            print_profiles(&profiles)?;
        }

        for warning in warnings {
            sh_warn!("{warning}")?;
        }

        Ok(())
    }

    async fn replay_transaction_locally(
        &self,
        tx_hash: TxHash,
    ) -> Result<super::run::ReplayTxResult> {
        replay_transaction(
            self.rpc.clone().into_figment(self.with_local_artifacts),
            ReplayTxArgs {
                tx_hash,
                debug: false,
                decode_internal: self.decode_internal,
                trace_printer: self.trace_printer,
                quick: false,
                replay_system_txes: false,
                evm_version: None,
                compute_units_per_second: if self.rpc.common.no_rpc_rate_limit {
                    Some(u64::MAX)
                } else {
                    self.rpc.common.compute_units_per_second
                },
                disable_block_gas_limit: false,
                enable_tx_gas_limit: false,
            },
        )
        .await
    }

    fn struct_logger_options(&self) -> GethDebugTracingOptions {
        GethDebugTracingOptions {
            config: GethDefaultTracingOptions::default()
                .with_disable_stack(false)
                .with_disable_storage(true)
                .with_enable_memory(self.enable_memory)
                .with_enable_return_data(false),
            ..Default::default()
        }
    }

    async fn fetch_call_trace<P, N>(
        &self,
        provider: &P,
        tx_hash: TxHash,
    ) -> (Option<GethTrace>, Option<String>)
    where
        P: Provider<N>,
        N: Network,
    {
        match provider
            .debug_trace_transaction(
                tx_hash,
                GethDebugTracingOptions::call_tracer(CallConfig::default().with_log()),
            )
            .await
        {
            Ok(trace) => (Some(trace), None),
            Err(err) => (None, Some(format!("debug_traceTransaction callTracer failed: {err}"))),
        }
    }

    async fn fetch_struct_trace<P, N>(
        &self,
        provider: &P,
        tx_hash: TxHash,
    ) -> (Option<GethTrace>, Option<String>)
    where
        P: Provider<N>,
        N: Network,
    {
        match provider.debug_trace_transaction(tx_hash, self.struct_logger_options()).await {
            Ok(trace) => (Some(trace), None),
            Err(err) if is_trace_response_too_big(&err) => (
                None,
                Some(
                    "debug_traceTransaction default struct logger exceeded provider limits; falling back to local replay for opcode steps".to_string(),
                ),
            ),
            Err(err) => (
                None,
                Some(format!("debug_traceTransaction default struct logger failed: {err}")),
            ),
        }
    }

    async fn fetch_storage_values<P, N>(&self, provider: &P, tx_hash: TxHash) -> Result<GethTrace>
    where
        P: Provider<N>,
        N: Network,
    {
        provider
            .debug_trace_transaction(
                tx_hash,
                GethDebugTracingOptions::prestate_tracer(PreStateConfig {
                    diff_mode: Some(true),
                    disable_storage: Some(false),
                    ..Default::default()
                }),
            )
            .await
            .wrap_err("debug_traceTransaction prestateTracer failed")
    }

    async fn load_or_fetch_raw_traces<P, N>(
        &self,
        provider: &P,
        tx_hash: TxHash,
    ) -> Result<RawRpcTraceCache>
    where
        P: Provider<N>,
        N: Network,
    {
        if self.has_explicit_local_json_inputs() {
            return self.load_from_explicit_local_json(provider, tx_hash).await;
        }

        if let Some(path) = self.raw_rpc_cache.as_ref()
            && !self.refresh_rpc_trace_cache
            && path.exists()
        {
            return read_json_file(path)
                .wrap_err_with(|| format!("failed to parse raw RPC cache {}", path.display()));
        }

        let chain_id = provider.get_chain_id().await?;
        let fetch_plan = self.metadata_fetch_plan();
        let tx = if fetch_plan.tx {
            let tx: Option<Value> =
                provider.raw_request(Cow::Borrowed("eth_getTransactionByHash"), (tx_hash,)).await?;
            tx.ok_or_else(|| eyre::eyre!("tx not found: {tx_hash:?}"))?
        } else {
            Value::Null
        };
        let block_number = if fetch_plan.tx {
            Some(
                block_number_from_tx(&tx)
                    .ok_or_else(|| eyre::eyre!("tx may still be pending: {tx_hash:?}"))?,
            )
        } else {
            None
        };

        let cache_path = self.raw_rpc_cache.clone().or_else(|| {
            if fetch_plan.automatic_cache {
                block_number
                    .and_then(|number| self.automatic_raw_rpc_cache_path(chain_id, number, tx_hash))
            } else {
                None
            }
        });
        if let Some(path) = cache_path.as_ref()
            && !self.refresh_rpc_trace_cache
            && path.exists()
        {
            return read_json_file(path)
                .wrap_err_with(|| format!("failed to parse raw RPC cache {}", path.display()));
        }

        let receipt = if fetch_plan.receipt {
            let receipt: Option<Value> = provider
                .raw_request(Cow::Borrowed("eth_getTransactionReceipt"), (tx_hash,))
                .await?;
            receipt.ok_or_else(|| eyre::eyre!("receipt not found for tx: {tx_hash:?}"))?
        } else {
            Value::Null
        };
        let block = if fetch_plan.block {
            let block_number =
                block_number.ok_or_else(|| eyre::eyre!("missing tx metadata for block lookup"))?;
            let block_number_hex = format!("0x{block_number:x}");
            let block: Option<Value> = provider
                .raw_request(Cow::Borrowed("eth_getBlockByNumber"), (block_number_hex, false))
                .await?;
            block.ok_or_else(|| eyre::eyre!("block not found for tx: {tx_hash:?}"))?
        } else {
            Value::Null
        };

        let (call_trace, call_trace_warning) = self.fetch_call_trace(provider, tx_hash).await;
        let (struct_trace, struct_trace_warning) = self.fetch_struct_trace(provider, tx_hash).await;

        let storage_values = if self.storage_values {
            Some(self.fetch_storage_values(provider, tx_hash).await?)
        } else {
            None
        };

        let raw = RawRpcTraceCache {
            chain_id,
            tx,
            receipt,
            block,
            call_trace,
            call_trace_warning,
            struct_trace,
            struct_trace_warning,
            storage_values,
        };

        if let Some(path) = cache_path {
            write_raw_rpc_cache(&path, &raw)?;
        }

        Ok(raw)
    }

    fn has_explicit_local_json_inputs(&self) -> bool {
        self.call_trace_json.is_some()
            || self.struct_trace_json.is_some()
            || self.storage_values_json.is_some()
            || self.tx_json.is_some()
            || self.receipt_json.is_some()
            || self.block_json.is_some()
    }

    async fn load_from_explicit_local_json<P, N>(
        &self,
        provider: &P,
        tx_hash: TxHash,
    ) -> Result<RawRpcTraceCache>
    where
        P: Provider<N>,
        N: Network,
    {
        let chain_id = provider.get_chain_id().await?;
        let fetch_plan = self.metadata_fetch_plan();

        let tx: Value = if let Some(path) = self.tx_json.as_ref() {
            read_json_file(path)
                .wrap_err_with(|| format!("failed to parse tx JSON {}", path.display()))?
        } else if fetch_plan.tx {
            let tx: Option<Value> =
                provider.raw_request(Cow::Borrowed("eth_getTransactionByHash"), (tx_hash,)).await?;
            tx.ok_or_else(|| eyre::eyre!("tx not found: {tx_hash:?}"))?
        } else {
            Value::Null
        };

        let block_number = if !tx.is_null() {
            Some(
                block_number_from_tx(&tx)
                    .ok_or_else(|| eyre::eyre!("tx may still be pending: {tx_hash:?}"))?,
            )
        } else {
            None
        };

        let receipt: Value = if let Some(path) = self.receipt_json.as_ref() {
            read_json_file(path)
                .wrap_err_with(|| format!("failed to parse receipt JSON {}", path.display()))?
        } else if fetch_plan.receipt {
            let receipt: Option<Value> = provider
                .raw_request(Cow::Borrowed("eth_getTransactionReceipt"), (tx_hash,))
                .await?;
            receipt.ok_or_else(|| eyre::eyre!("receipt not found for tx: {tx_hash:?}"))?
        } else {
            Value::Null
        };

        let block: Value = if let Some(path) = self.block_json.as_ref() {
            read_json_file(path)
                .wrap_err_with(|| format!("failed to parse block JSON {}", path.display()))?
        } else if fetch_plan.block {
            let block_number =
                block_number.ok_or_else(|| eyre::eyre!("missing tx metadata for block lookup"))?;
            let block_number_hex = format!("0x{block_number:x}");
            let block: Option<Value> = provider
                .raw_request(Cow::Borrowed("eth_getBlockByNumber"), (block_number_hex, false))
                .await?;
            block.ok_or_else(|| eyre::eyre!("block not found for tx: {tx_hash:?}"))?
        } else {
            Value::Null
        };

        let (call_trace, call_trace_warning) = if let Some(path) = self.call_trace_json.as_ref() {
            (
                Some(read_json_file(path).wrap_err_with(|| {
                    format!("failed to parse call trace JSON {}", path.display())
                })?),
                None,
            )
        } else {
            self.fetch_call_trace(provider, tx_hash).await
        };

        let (struct_trace, struct_trace_warning) =
            if let Some(path) = self.struct_trace_json.as_ref() {
                (
                    Some(read_json_file(path).wrap_err_with(|| {
                        format!("failed to parse struct trace JSON {}", path.display())
                    })?),
                    None,
                )
            } else {
                self.fetch_struct_trace(provider, tx_hash).await
            };

        let storage_values = if let Some(path) = self.storage_values_json.as_ref() {
            Some(read_json_file(path).wrap_err_with(|| {
                format!("failed to parse storage values JSON {}", path.display())
            })?)
        } else if self.storage_values {
            Some(self.fetch_storage_values(provider, tx_hash).await?)
        } else {
            None
        };

        let raw = RawRpcTraceCache {
            chain_id,
            tx,
            receipt,
            block,
            call_trace,
            call_trace_warning,
            struct_trace,
            struct_trace_warning,
            storage_values,
        };

        let cache_path = self.raw_rpc_cache.clone().or_else(|| {
            if fetch_plan.automatic_cache {
                block_number
                    .and_then(|number| self.automatic_raw_rpc_cache_path(chain_id, number, tx_hash))
            } else {
                None
            }
        });
        if let Some(path) = cache_path {
            write_raw_rpc_cache(&path, &raw)?;
        }

        Ok(raw)
    }

    fn metadata_fetch_plan(&self) -> MetadataFetchPlan {
        let automatic_cache = !self.no_rpc_trace_cache && !self.quick;
        let persistent_cache = self.raw_rpc_cache.is_some();
        let json_output = shell::is_json();

        MetadataFetchPlan {
            tx: self.with_local_artifacts || json_output || persistent_cache || automatic_cache,
            receipt: json_output || !self.quick || persistent_cache,
            block: json_output || persistent_cache,
            automatic_cache,
        }
    }

    fn automatic_raw_rpc_cache_path(
        &self,
        chain_id: u64,
        block_number: u64,
        tx_hash: TxHash,
    ) -> Option<PathBuf> {
        if self.no_rpc_trace_cache || self.quick {
            return None;
        }

        Config::foundry_block_cache_dir(chain_id, block_number).map(|dir| {
            dir.join("trace-rpc").join(format!(
                "{}-{}.json",
                tx_hash,
                raw_rpc_cache_tracer_key(self.storage_values, self.enable_memory)
            ))
        })
    }

    async fn rpc_refund_quotient<P, N>(&self, provider: &P, raw: &RawRpcTraceCache) -> Result<u64>
    where
        P: Provider<N>,
        N: Network,
    {
        let Some(timestamp) = self.rpc_trace_block_timestamp(provider, raw).await? else {
            return Ok(5);
        };
        let Some(hardfork) = FoundryHardfork::from_chain_and_timestamp(raw.chain_id, timestamp)
        else {
            return Ok(5);
        };

        Ok(if is_post_london_spec(hardfork.into()) { 5 } else { 2 })
    }

    async fn rpc_trace_block_timestamp<P, N>(
        &self,
        provider: &P,
        raw: &RawRpcTraceCache,
    ) -> Result<Option<u64>>
    where
        P: Provider<N>,
        N: Network,
    {
        if let Some(timestamp) = block_timestamp_from_block(&raw.block) {
            return Ok(Some(timestamp));
        }

        let Some(block_number) = block_number_from_tx(&raw.tx) else {
            return Ok(None);
        };
        let block_number_hex = format!("0x{block_number:x}");
        let block: Option<Value> = provider
            .raw_request(Cow::Borrowed("eth_getBlockByNumber"), (block_number_hex, false))
            .await?;
        Ok(block.as_ref().and_then(block_timestamp_from_block))
    }
}

fn raw_rpc_cache_tracer_key(storage_values: bool, enable_memory: bool) -> &'static str {
    match (storage_values, enable_memory) {
        (false, false) => "call-struct-v1",
        (false, true) => "call-struct-memory-v1",
        (true, false) => "call-struct-prestate-diff-v1",
        (true, true) => "call-struct-memory-prestate-diff-v1",
    }
}

fn is_trace_response_too_big(err: &impl std::fmt::Display) -> bool {
    let msg = err.to_string();
    (msg.contains("-32008") && msg.to_ascii_lowercase().contains("too big"))
        || msg.contains("Exceeded max limit")
}

fn write_raw_rpc_cache(path: &Path, raw: &RawRpcTraceCache) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).wrap_err_with(|| {
            format!("failed to create raw RPC cache directory {}", parent.display())
        })?;
    }
    let file = File::create(path)
        .wrap_err_with(|| format!("failed to write raw RPC cache {}", path.display()))?;
    serde_json::to_writer_pretty(BufWriter::new(file), raw)
        .wrap_err_with(|| format!("failed to serialize raw RPC cache {}", path.display()))?;
    Ok(())
}

fn read_json_file<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let file = File::open(path).wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let reader = BufReader::new(file);
    match serde_json::from_reader::<_, JsonFileInput<T>>(reader)
        .wrap_err_with(|| format!("failed to parse {}", path.display()))?
    {
        JsonFileInput::Raw(value) | JsonFileInput::RpcSuccess { result: value } => Ok(value),
        JsonFileInput::RpcError { error } => {
            eyre::bail!("{} contains a JSON-RPC error response: {error}", path.display())
        }
    }
}

fn execution_trace(result: &TraceResult) -> Option<&foundry_evm::traces::SparsedTraceArena> {
    result.traces.as_ref()?.iter().find_map(|(kind, arena)| kind.is_execution().then_some(arena))
}

async fn fetch_contracts_bytecode<P, N>(
    provider: &P,
    result: &TraceResult,
    block_number: Option<u64>,
) -> HashMap<Address, Bytes>
where
    P: Provider<N>,
    N: Network,
{
    let mut bytecodes = HashMap::default();
    let block_id = block_number.map(|number| BlockId::Number(BlockNumberOrTag::Number(number)));
    let Some(traces) = result.traces.as_ref() else {
        return bytecodes;
    };

    let mut addresses = Vec::new();
    for address in traces.iter().flat_map(|(_, arena)| arena.trace_addresses()) {
        if address.is_zero() || bytecodes.contains_key(&address) {
            continue;
        }
        bytecodes.insert(address, Bytes::new());
        addresses.push(address);
    }
    bytecodes.clear();

    let mut requests = futures::stream::iter(addresses.into_iter().map(|address| {
        let block_id = block_id;
        async move {
            let mut code_req = provider.get_code_at(address);
            if let Some(block_id) = block_id {
                code_req = code_req.block_id(block_id);
            }
            (address, code_req.await)
        }
    }))
    .buffer_unordered(16);

    while let Some((address, result)) = requests.next().await {
        match result {
            Ok(code) if !code.is_empty() => {
                bytecodes.insert(address, code);
            }
            Ok(_) => {}
            Err(err) => {
                let _ = sh_warn!("failed to fetch bytecode for {address}: {err}");
            }
        }
    }

    bytecodes
}

fn gas_used_from_receipt(receipt: &Value) -> Option<u64> {
    quantity_to_u64(receipt.get("gasUsed")?)
}

fn block_number_from_tx(tx: &Value) -> Option<u64> {
    quantity_to_u64(tx.get("blockNumber")?)
}

fn block_timestamp_from_block(block: &Value) -> Option<u64> {
    quantity_to_u64(block.get("timestamp")?)
}

fn is_post_london_spec(spec_id: SpecId) -> bool {
    (spec_id as u8) >= (SpecId::LONDON as u8)
}

fn quantity_to_u64(value: &Value) -> Option<u64> {
    let raw = value.as_str()?.strip_prefix("0x").unwrap_or(value.as_str()?);
    u64::from_str_radix(raw, 16).ok()
}

fn print_profiles(profiles: &RpcTraceProfiles) -> Result<()> {
    sh_println!("\nGas by function:")?;
    for function in profiles.functions.iter().take(25) {
        sh_println!(
            "{:>12} gas  {:>12} self  {:>8} calls  {}::{}",
            function.inclusive_gas,
            function.self_gas,
            function.call_count,
            function.contract_name,
            function.function_name
        )?;
    }

    sh_println!("\nGas by opcode:")?;
    for opcode in profiles.opcodes.iter().take(25) {
        sh_println!("{:>12} gas  {:>8} hits  {}", opcode.gas_used, opcode.count, opcode.opcode)?;
    }

    if !profiles.storage_slots.is_empty() {
        sh_println!("\nMost touched storage slots:")?;
        for slot in profiles.storage_slots.iter().take(25) {
            sh_println!(
                "{:>8} touches  {:>8} reads  {:>8} writes  {:>12} gas  {}:{}",
                slot.touches,
                slot.reads,
                slot.writes,
                slot.gas_used,
                slot.storage_address,
                slot.slot
            )?;
        }
    }

    if !profiles.transient_storage_slots.is_empty() {
        sh_println!("\nMost touched transient storage slots:")?;
        for slot in profiles.transient_storage_slots.iter().take(25) {
            sh_println!(
                "{:>8} touches  {:>8} reads  {:>8} writes  {:>12} gas  {}:{}",
                slot.touches,
                slot.reads,
                slot.writes,
                slot.gas_used,
                slot.storage_address,
                slot.slot
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_cache_path_uses_tracer_shape() {
        let tx_hash: TxHash =
            "0x296fccbf5246af0dbd964fdaf698d8c16f1841159385116818c345deea92fb76".parse().unwrap();

        let without_storage =
            run_trace_args(false, false).automatic_raw_rpc_cache_path(4153, 123, tx_hash).unwrap();
        assert_eq!(
            without_storage.file_name().unwrap().to_str().unwrap(),
            "0x296fccbf5246af0dbd964fdaf698d8c16f1841159385116818c345deea92fb76-call-struct-v1.json"
        );

        let with_storage =
            run_trace_args(true, false).automatic_raw_rpc_cache_path(4153, 123, tx_hash).unwrap();
        assert_eq!(
            with_storage.file_name().unwrap().to_str().unwrap(),
            "0x296fccbf5246af0dbd964fdaf698d8c16f1841159385116818c345deea92fb76-call-struct-prestate-diff-v1.json"
        );

        let with_memory = run_trace_args(false, false)
            .with_memory()
            .automatic_raw_rpc_cache_path(4153, 123, tx_hash)
            .unwrap();
        assert_eq!(
            with_memory.file_name().unwrap().to_str().unwrap(),
            "0x296fccbf5246af0dbd964fdaf698d8c16f1841159385116818c345deea92fb76-call-struct-memory-v1.json"
        );
    }

    #[test]
    fn automatic_cache_can_be_disabled() {
        let tx_hash: TxHash =
            "0x296fccbf5246af0dbd964fdaf698d8c16f1841159385116818c345deea92fb76".parse().unwrap();
        assert!(
            run_trace_args(false, true).automatic_raw_rpc_cache_path(4153, 123, tx_hash).is_none()
        );
    }

    #[test]
    fn quick_mode_skips_automatic_cache_and_optional_metadata() {
        let args = run_trace_args(false, false).with_quick();
        let tx_hash: TxHash =
            "0x296fccbf5246af0dbd964fdaf698d8c16f1841159385116818c345deea92fb76".parse().unwrap();

        assert!(args.automatic_raw_rpc_cache_path(4153, 123, tx_hash).is_none());
        assert_eq!(
            args.metadata_fetch_plan(),
            MetadataFetchPlan { tx: false, receipt: false, block: false, automatic_cache: false }
        );
    }

    #[test]
    fn detects_oversized_trace_errors() {
        assert!(is_trace_response_too_big(
            &"server returned an error response: error code -32008: Response is too big, data: \"Exceeded max limit of 167772160\""
        ));
        assert!(!is_trace_response_too_big(&"execution reverted"));
    }

    fn run_trace_args(storage_values: bool, no_rpc_trace_cache: bool) -> RunTraceArgs {
        RunTraceArgs {
            tx_hash: None,
            decode_internal: false,
            trace_depth: None,
            trace_printer: false,
            quick: false,
            disable_labels: false,
            label: Vec::new(),
            with_local_artifacts: false,
            profile: false,
            no_storage_profile: false,
            storage_values,
            enable_memory: false,
            raw_rpc_cache: None,
            call_trace_json: None,
            struct_trace_json: None,
            storage_values_json: None,
            tx_json: None,
            receipt_json: None,
            block_json: None,
            no_rpc_trace_cache,
            refresh_rpc_trace_cache: false,
            allow_bytecode_mismatch: false,
            rpc: RpcOpts::default(),
        }
    }

    trait RunTraceArgsTestExt {
        fn with_memory(self) -> Self;
        fn with_quick(self) -> Self;
    }

    impl RunTraceArgsTestExt for RunTraceArgs {
        fn with_memory(mut self) -> Self {
            self.enable_memory = true;
            self
        }

        fn with_quick(mut self) -> Self {
            self.quick = true;
            self
        }
    }
}
