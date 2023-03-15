use anchor_lang::prelude::*;

use light_macros::light_verifier_accounts;

#[light_verifier_accounts]
#[derive(Accounts)]
pub struct LightInstruction<'info> {
    #[account(mut)]
    pub signing_address: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[test]
fn test_noop() {}
