//! The demo action, seen from inside the sandbox.
//!
//! This guest holds capability *handles* — the signing key, the file grant, everything real stays
//! host-side. Its WASI is empty (no fs, no net, no env); `caps` is the only door to the world.

wit_bindgen::generate!({ path: "../wit/action", world: "action" });

use crate::warden::action::caps;

struct Demo;

impl Guest for Demo {
    fn run() -> Result<(), String> {
        // sign a release manifest with a key this guest can never see
        let sign = caps::get("sign").ok_or("no sign capability granted")?;
        let mac = sign.invoke("sign", b"release manifest v1.2.3")?;
        println!("  [guest] signature: {}", String::from_utf8_lossy(&mac));

        // the interface has no op that returns the key — prove it
        match sign.invoke("reveal", &[]) {
            Err(e) => println!("  [guest] `reveal` refused: {e}"),
            Ok(_) => return Err("reveal unexpectedly allowed".into()),
        }

        // read the config through fs.read — DLP-masked before it ever reaches this sandbox
        let fs = caps::get("fs.read").ok_or("no fs.read capability granted")?;
        let cfg = fs.invoke("read", &[])?;
        println!("  [guest] config as seen from the sandbox: {:?}", String::from_utf8_lossy(&cfg));

        // a capability that was never granted simply doesn't exist here
        if caps::get("exec").is_none() {
            println!("  [guest] exec? not granted — it does not exist in this world");
        }
        Ok(())
    }
}

export!(Demo);
