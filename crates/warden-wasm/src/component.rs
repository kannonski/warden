//! The component-model runtime: `wit/warden.wit`, capabilities as resource handles.
//!
//! The guest's `capability` is an opaque handle in a host-side [`ResourceTable`]; the entry holds
//! only a [`CapId`]. The real object (file grant, pinned binary, signing key) stays inside the
//! warden's [`Ctx`] — the guest can name it, never touch it. Every `invoke` crosses `Ctx::invoke`.

// NB: warden_core::Result (a 1-param alias) must NOT be imported here — the bindgen-generated
// code below references `Result<_, _>` unqualified and would resolve to the alias.
use warden_core::{ActionSource, CapId, Ctx, Runtime, WardenError};
use wasmtime::Store;
use wasmtime::component::{Component, Linker, Resource, ResourceTable};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "action",
    with: { "warden:action/caps/capability": CapEntry },
});

/// What a guest-held `capability` handle points at, host-side: just the id.
pub struct CapEntry {
    id: CapId,
}

struct State {
    /// `&Ctx` stored as an address so `State` stays `Send` (wasi bounds). SAFETY: set from a
    /// borrow that outlives the `Store`, which lives strictly inside [`ComponentRuntime::run`].
    ctx: usize,
    table: ResourceTable,
    wasi: WasiCtx,
}
impl State {
    fn warden(&self) -> &Ctx {
        unsafe { &*(self.ctx as *const Ctx) }
    }
}
impl WasiView for State {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

impl warden::action::caps::Host for State {
    fn get(&mut self, kind: String) -> Option<Resource<CapEntry>> {
        let id = self.warden().cap_by_name(&kind)?;
        Some(
            self.table
                .push(CapEntry { id })
                .expect("resource table push"),
        )
    }
}

impl warden::action::caps::HostCapability for State {
    fn invoke(
        &mut self,
        cap: Resource<CapEntry>,
        op: String,
        input: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, String> {
        let id = self.table.get(&cap).expect("live resource").id;
        self.warden()
            .invoke(id, &op, input)
            .map_err(|e| e.to_string())
    }

    fn drop(&mut self, cap: Resource<CapEntry>) -> wasmtime::Result<()> {
        self.table.delete(cap)?;
        Ok(())
    }
}

pub struct ComponentRuntime;

impl Runtime for ComponentRuntime {
    fn name(&self) -> &'static str {
        "component"
    }

    fn run(&self, action: warden_core::Action, ctx: &Ctx) -> warden_core::Result<()> {
        let bytes = match action.source {
            ActionSource::Wasm(b) => b,
            _ => {
                return Err(WardenError::Cap(
                    "component runtime requires a Wasm action".into(),
                ));
            }
        };

        let engine = wasmtime::Engine::default();
        let component = Component::new(&engine, &bytes)
            .map_err(|e| WardenError::Cap(format!("component compile: {e}")))?;

        let mut linker: Linker<State> = Linker::new(&engine);
        // WASI, granted EMPTY: no preopened dirs, no net, no env — stdout/stderr inherited only so
        // the demo guest's prints are visible. The `caps` interface is the guest's sole door.
        wasmtime_wasi::add_to_linker_sync(&mut linker)
            .map_err(|e| WardenError::Cap(format!("wasi link: {e}")))?;
        Action::add_to_linker(&mut linker, |s: &mut State| s)
            .map_err(|e| WardenError::Cap(format!("caps link: {e}")))?;

        let wasi = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build();
        let mut store = Store::new(
            &engine,
            State {
                ctx: ctx as *const Ctx as usize,
                table: ResourceTable::new(),
                wasi,
            },
        );

        let instance = Action::instantiate(&mut store, &component, &linker)
            .map_err(|e| WardenError::Cap(format!("component instantiate: {e}")))?;
        instance
            .call_run(&mut store)
            .map_err(|e| WardenError::Cap(format!("component trap: {e}")))?
            .map_err(|e| WardenError::Cap(format!("action failed: {e}")))
    }
}
