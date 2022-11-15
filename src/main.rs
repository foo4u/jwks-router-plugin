mod jwks_manager;
mod plugins;

use anyhow::Result;

fn main() -> Result<()> {
    apollo_router::main()
}
