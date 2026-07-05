//! warden-secret — secrets as capabilities.
//!
//! The action never asks for a secret; it asks for an **operation over a secret**. Here: `sign` —
//! request the capability by secret name, invoke `sign(payload)`, get an HMAC back. The interface
//! has no op that returns key material, so the boundary is structural, not behavioral: the record
//! shows every use (payload in, MAC out) and can never contain the key on the output side.
//!
//! Honest boundary (recorded in the design): the secret is isolated from the **action**, not from
//! the **warden** — the warden must hold the plaintext to use it (warden-blind = TEE/HSM, a later
//! tier). And the vault seam is for *integration*: pull short-lived/dynamic credentials from a real
//! vault; don't rebuild secret storage.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use warden_core::{Broker, CapKind, CapRequest, Capability, OpSpec, Result, WardenError};

pub const SIGN: CapKind = CapKind("sign");

// ── the vault seam ──────────────────────────────────────────────────────────────────────────────

/// Where brokers pull secrets from. Product impls integrate real vaults (OpenBao/Vault, cloud SM)
/// and return short-lived leases with TTL + renewal; the spike keeps the seam and stubs the store.
pub trait Vault: Send + Sync {
    fn fetch(&self, name: &str) -> Option<Vec<u8>>;
}

/// In-memory vault for the spike/tests.
pub struct MemVault(HashMap<String, Vec<u8>>);
impl MemVault {
    pub fn new(entries: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self(entries.into_iter().collect())
    }
}
impl Vault for MemVault {
    fn fetch(&self, name: &str) -> Option<Vec<u8>> {
        self.0.get(name).cloned()
    }
}

// ── the sign capability + its broker ────────────────────────────────────────────────────────────

pub struct SignCap {
    /// `None` after revocation. Best-effort zeroized on revoke — real impl uses the zeroize crate
    /// plus mlock/no-swap so key material can't linger in memory or hit disk.
    key: Mutex<Option<Vec<u8>>>,
}
// The contract IS the design: `sign` is the only op. There is deliberately no `reveal`/`export`/`key`
// op — the key never leaves the host, and now that's a positive fact in the published op set, not just
// a refusal buried in a match arm. Signing observes the key but doesn't change the world → not mutating.
const OPS: &[OpSpec] = &[OpSpec {
    op: "sign",
    doc: "HMAC-SHA256 the input with the vaulted key (never returns the key)",
    mutates: false,
}];

#[async_trait]
impl Capability for SignCap {
    fn kind(&self) -> CapKind {
        SIGN
    }
    fn ops(&self) -> &'static [OpSpec] {
        OPS
    }
    async fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>> {
        // kernel validates first; this defends the cap in isolation too (see `no_such_op`)
        if op != "sign" {
            return Err(warden_core::no_such_op(SIGN, op));
        }
        let guard = self.key.lock().unwrap();
        let key = guard
            .as_ref()
            .ok_or(WardenError::Cap("sign capability revoked".into()))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| WardenError::Cap(format!("hmac init: {e}")))?;
        mac.update(input);
        let out: Vec<u8> = mac.finalize().into_bytes().to_vec();
        Ok(out
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .into_bytes())
    }
    fn revoke(&self) {
        if let Some(mut key) = self.key.lock().unwrap().take() {
            // volatile writes so the wipe isn't optimized away (best-effort; see zeroize note above)
            for b in key.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
        }
    }
}

pub struct SignBroker {
    vault: Arc<dyn Vault>,
}
impl SignBroker {
    pub fn new(vault: Arc<dyn Vault>) -> Self {
        Self { vault }
    }
}
#[async_trait]
impl Broker for SignBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == SIGN
    }
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        let key = self.vault.fetch(&req.arg).ok_or_else(|| {
            WardenError::Cap(format!("vault has no secret `{}` — grant refused", req.arg))
        })?;
        Ok(Box::new(SignCap {
            key: Mutex::new(Some(key)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn cap() -> Box<dyn Capability> {
        let vault = Arc::new(MemVault::new([("k".to_string(), b"topsecretkey".to_vec())]));
        SignBroker::new(vault)
            .grant(&CapRequest {
                kind: SIGN,
                arg: "k".into(),
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn signs_but_never_reveals() {
        let c = cap().await;
        let mac = c.perform("sign", b"payload").await.unwrap();
        assert_eq!(mac.len(), 64); // hex-encoded hmac-sha256
        assert!(
            !String::from_utf8_lossy(&mac).contains("topsecret"),
            "key leaked into output"
        );
        // no op returns the key
        for op in ["reveal", "read", "export", "key"] {
            assert!(
                c.perform(op, &[]).await.is_err(),
                "`{op}` should be refused"
            );
        }
        // deterministic: same input, same mac
        assert_eq!(c.perform("sign", b"payload").await.unwrap(), mac);
    }

    #[tokio::test]
    async fn unknown_secret_refuses_grant_and_revoke_kills_signing() {
        let vault = Arc::new(MemVault::new([("k".to_string(), b"x".to_vec())]));
        let broker = SignBroker::new(vault);
        assert!(
            broker
                .grant(&CapRequest {
                    kind: SIGN,
                    arg: "nope".into()
                })
                .await
                .is_err()
        );

        let c = cap().await;
        c.revoke();
        assert!(
            c.perform("sign", b"p").await.is_err(),
            "revoked cap must not sign"
        );
    }
}
