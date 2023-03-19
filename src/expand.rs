use anchor_syn::AccountsStruct;
use bs58::decode;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse::Parse, parse_quote, Error, Field, ItemStruct, LitStr, Result};

const PUBKEY_LEN: usize = 32;

pub(crate) struct PubkeyArgs {
    pub(crate) pubkey: LitStr,
}

impl Parse for PubkeyArgs {
    fn parse(input: syn::parse::ParseStream) -> Result<Self> {
        Ok(Self {
            pubkey: input.parse()?,
        })
    }
}

pub(crate) fn pubkey(args: PubkeyArgs) -> Result<TokenStream> {
    let v = decode(args.pubkey.value())
        .into_vec()
        .map_err(|_| Error::new(args.pubkey.span(), "Invalid base58 string"))?;
    let v_len = v.len();

    let arr: [u8; PUBKEY_LEN] = v.try_into().map_err(|_| {
        Error::new(
            args.pubkey.span(),
            format!(
                "Invalid size of decoded public key, expected 32, got {}",
                v_len,
            ),
        )
    })?;

    Ok(quote! {
        ::anchor_lang::prelude::Pubkey::new_from_array([ #(#arr),* ])
    })
}

pub(crate) struct LightVerifierAccountsArgs {}

impl Parse for LightVerifierAccountsArgs {
    fn parse(_input: syn::parse::ParseStream) -> Result<Self> {
        Ok(Self {})
    }
}

pub(crate) fn light_verifier_accounts(
    _args: LightVerifierAccountsArgs,
    strct: ItemStruct,
    mut accounts_strct: AccountsStruct,
) -> Result<TokenStream> {
    // This `anchor_syn::AccountsStruct` instance is created only to provide
    // our own common fields (which we want to append to the original struct
    // provided as the `item` argument). We define our fields there and then
    // parse them with `parse_quote!` macro.
    let common_fields = quote! {
        pub struct CommonFields {
            /// CHECK: Is the same as in integrity hash.
            pub program_merkle_tree: Program<'info, ::merkle_tree_program::program::MerkleTreeProgram>,
            /// CHECK: Is the same as in integrity hash.
            #[account(mut)]
            pub merkle_tree: AccountLoader<'info, ::merkle_tree_program::poseidon_merkle_tree::state::MerkleTree>,
            /// CHECK: This is the cpi authority and will be enforced in the Merkle tree program.
            #[account(
                mut,
                seeds=[::merkle_tree_program::program::MerkleTreeProgram::id().to_bytes().as_ref()],
                bump
            )]
            pub authority: UncheckedAccount<'info>,
            pub token_program: Program<'info, ::anchor_spl::token::Token>,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[account(mut)]
            pub sender: UncheckedAccount<'info>,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[account(mut)]
            pub recipient: UncheckedAccount<'info>,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[account(mut)]
            pub sender_fee: UncheckedAccount<'info>,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[account(mut)]
            pub recipient_fee: UncheckedAccount<'info>,
            /// CHECK: Is not checked the relayer has complete freedom.
            #[account(mut)]
            pub relayer_recipient: UncheckedAccount<'info>,
            /// CHECK: Is checked when it is used during spl withdrawals.
            #[account(
                mut,
                seeds=[::merkle_tree_program::utils::constants::TOKEN_AUTHORITY_SEED],
                bump,
                seeds::program=::merkle_tree_program::program::MerkleTreeProgram::id()
            )]
            pub token_authority: AccountInfo<'info>,
            /// Verifier config pda which needs ot exist Is not checked the relayer has complete freedom.
            /// CHECK: Is the same as in integrity hash.
            #[account(
                mut,
                seeds=[program_id.key().to_bytes().as_ref()],
                bump,
                seeds::program=::merkle_tree_program::program::MerkleTreeProgram::id()
            )]
            pub registered_verifier_pda: Account<
                'info,
                ::merkle_tree_program::config_accounts::register_verifier::RegisteredVerifier
            >,
        }
    };
    let common_fields_strct: ItemStruct = parse_quote! {
        #common_fields
    };
    let common_fields_accounts_strct: AccountsStruct = parse_quote! {
        #common_fields
    };

    let strct_attrs = &strct.attrs;
    let strct_vis = &strct.vis;
    let strct_token = &strct.struct_token;
    let strct_ident = &strct.ident;
    let strct_generics = &strct.generics;
    let mut strct_fields: Vec<Field> = Vec::new();

    // Remove attributes from all fields, to avoid `not a non-macro attribute`
    // errors. We don't use any non-macro attributes in structs that implement
    // Anchor's `Accounts` deserializer anyway.
    for field in strct.fields.iter() {
        let field = Field {
            attrs: Vec::new(),
            vis: field.vis.clone(),
            ident: field.ident.clone(),
            colon_token: field.colon_token.clone(),
            ty: field.ty.clone(),
        };
        strct_fields.push(field);
    }
    for field in common_fields_strct.fields.iter() {
        let field = Field {
            attrs: Vec::new(),
            vis: field.vis.clone(),
            ident: field.ident.clone(),
            colon_token: field.colon_token.clone(),
            ty: field.ty.clone(),
        };
        strct_fields.push(field);
    }

    let strct_semi_token = &strct.semi_token;
    let strct = quote! {
        #( #strct_attrs )*
        #strct_vis #strct_token #strct_ident #strct_generics {
            #( #strct_fields ),*
        } #strct_semi_token
    };

    accounts_strct
        .fields
        .extend(common_fields_accounts_strct.fields);

    Ok(quote! {
        #strct

        #accounts_strct
    })
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_pubkey() {
        let res = pubkey(parse_quote! { "cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK" });
        assert_eq!(
            res.unwrap().to_string(),
            ":: anchor_lang :: prelude :: Pubkey :: new_from_array ([9u8 , 42u8 \
             , 19u8 , 238u8 , 149u8 , 196u8 , 28u8 , 186u8 , 8u8 , 166u8 , \
             127u8 , 90u8 , 198u8 , 126u8 , 141u8 , 247u8 , 225u8 , 218u8 , \
             17u8 , 98u8 , 94u8 , 29u8 , 100u8 , 19u8 , 127u8 , 143u8 , 79u8 , \
             35u8 , 131u8 , 3u8 , 127u8 , 20u8])",
        );
    }

    #[test]
    fn test_light_verifier_accounts() {
        let strct = quote! {
            struct LightInstruction {
                pub verifier_state: Signer<'info>,
            }
        };
        let res = light_verifier_accounts(
            parse_quote! {},
            parse_quote! {
                #strct
            },
            parse_quote! {
                #strct
            },
        )
        .expect("Failed to expand light_verifier_accounts")
        .to_string();

        println!("{}", res);

        assert!(res.contains("pub (crate) mod __cpi_client_accounts_light_instruction"));
    }
}
