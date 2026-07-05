//! warden-wasm — the WASM [`Runtime`] impls behind the `Runtime` seam.
//!
//! Two tiers, both routing every guest call into [`Ctx::invoke`] — the *same* mediation chokepoint
//! the in-process demo runtime uses, so guest calls are policy-gated, DLP-masked, and recorded
//! identically. Swapping wasmtime for another engine (or adding a native runtime) is a different
//! crate implementing [`Runtime`] — nothing in `warden-core` changes.
//!
//! - [`WasmRuntime`] (`"wasm"`): minimal core-module ABI (`invoke(op: i32) -> i32`, op-by-index on
//!   the first granted cap). Kept because it's fully self-contained — the demo embeds the guest as
//!   WAT. It proves the seam, not the interface.
//! - [`ComponentRuntime`] (`"component"`): the real ABI — component model + `wit/warden.wit`.
//!   Capabilities are **resource handles**: the guest holds an opaque handle and calls
//!   `capability.invoke(op, bytes)`; the actual resource (a file grant, a pinned binary, a signing
//!   key) lives host-side and never enters the guest's linear memory. WASI is granted EMPTY (no
//!   preopened dirs, no net, no env — stdout only, for demo prints): the `caps` interface is the
//!   guest's only door to the world, so least-privilege is structural.

mod component;
pub use component::ComponentRuntime;

use warden_core::{Action, ActionSource, Ctx, Result, Runtime, WardenError};
use wasmtime::{Caller, Engine, Linker, Module, Store};

/// Store data for the guest's host calls. Holds a pointer to the borrowed [`Ctx`] because the wasm
/// `Store` lives strictly inside [`WasmRuntime::run`], during which `ctx` is borrowed and outlives it.
struct HostState {
    ctx: *const Ctx,
}

pub struct WasmRuntime;

impl Runtime for WasmRuntime {
    fn name(&self) -> &'static str {
        "wasm"
    }

    fn run(&self, action: Action, ctx: &Ctx) -> Result<()> {
        let bytes = match action.source {
            ActionSource::Wasm(b) => b,
            _ => {
                return Err(WardenError::Cap(
                    "wasm runtime requires a Wasm action".into(),
                ));
            }
        };

        let engine = Engine::default();
        let module = Module::new(&engine, &bytes)
            .map_err(|e| WardenError::Cap(format!("wasm compile: {e}")))?;

        let mut linker: Linker<HostState> = Linker::new(&engine);
        linker
            .func_wrap(
                "warden",
                "invoke",
                |caller: Caller<'_, HostState>, op: i32| -> i32 {
                    // SAFETY: `ctx` is borrowed for all of `run()`, which owns the Store; the pointer is
                    // valid for every host call the guest makes during instantiation and execution.
                    let ctx: &Ctx = unsafe { &*caller.data().ctx };
                    let Some(cap) = ctx.first_cap() else {
                        return -1;
                    };
                    let op_name = match op {
                        0 => "read",
                        1 => "write",
                        _ => return -1,
                    };
                    match ctx.invoke(cap, op_name, Vec::new()) {
                        Ok(out) => out.len() as i32,
                        Err(_) => -1,
                    }
                },
            )
            .map_err(|e| WardenError::Cap(format!("wasm link: {e}")))?;

        let mut store = Store::new(
            &engine,
            HostState {
                ctx: ctx as *const Ctx,
            },
        );
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| WardenError::Cap(format!("wasm instantiate: {e}")))?;
        let run = instance
            .get_typed_func::<(), i32>(&mut store, "run")
            .map_err(|e| WardenError::Cap(format!("wasm entry `run`: {e}")))?;
        let ret = run
            .call(&mut store, ())
            .map_err(|e| WardenError::Cap(format!("wasm trap: {e}")))?;

        eprintln!("  [wasm] guest run() -> {ret}  (last op's result; -1 = refused by capability)");
        Ok(())
    }
}
