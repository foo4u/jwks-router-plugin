mod plugins;
mod jwks_manager;

use anyhow::Result;

fn main() -> Result<()> {
    apollo_router::main()
}
