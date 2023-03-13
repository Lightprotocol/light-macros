use bs58::decode;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse::Parse, Error, ItemStruct, LitStr, Result};

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
    item: ItemStruct,
) -> Result<TokenStream> {
    let attrs = &item.attrs;
    let vis = &item.vis;
    let struct_token = &item.struct_token;
    let ident = &item.ident;
    let generics = &item.generics;
    let fields = &item.fields;
    let semi_token = &item.semi_token;

    // NOTE(vadorovsky): Using `&item.fields.iter()` (as `#( #ident ),*` or
    // `#( #ident )*` or `#ident`) doesn't work... -_-
    let mut new_fields = Vec::new();
    for field in fields.iter() {
        new_fields.push(field);
    }

    Ok(quote! {
        #( #attrs )*
        #vis #struct_token #ident #generics {
            #( #new_fields ),* ,
            /// CHECK: Is the same as in integrity hash.
            pub program_merkle_tree: ::anchor_lang::prelude::Program<
                'info,
                ::merkle_tree_program::program::MerkleTreeProgram
            >,
            // CHECK: Is the same as in integrity hash.
            #[::anchor_lang::prelude::account(mut)]
            pub merkle_tree: ::anchor_lang::prelude::AccountLoader<
                'info,
                ::merkle_tree_program::poseidon_merkle_tree::state::MerkleTree
            >,
            /// CHECK: This is the cpi authority and will be enforced in the Merkle tree program.
            #[::anchor_lang::prelude::account(
                mut,
                seeds=[::merkle_tree_program::program::MerkleTreeProgram::id().to_bytes().as_ref()],
                bump
            )]
            pub authority: ::anchor_lang::prelude::UncheckedAccount<'info>,
            pub token_program: ::anchor_lang::prelude::Program<
                'info,
                ::anchor_lang::prelude::Token
            >,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[::anchor_lang::prelude::account(mut)]
            pub sender: ::anchor_lang::prelude::UncheckedAccount<'info>,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[::anchor_lang::prelude::account(mut)]
            pub recipient: ::anchor_lang::prelude::UncheckedAccount<'info>,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[::anchor_lang::prelude::account(mut)]
            pub sender_fee: ::anchor_lang::prelude::UncheckedAccount<'info>,
            /// CHECK: Is checked depending on deposit or withdrawal.
            #[::anchor_lang::prelude::account(mut)]
            pub recipient_fee: ::anchor_lang::prelude::UncheckedAccount<'info>,,
            /// CHECK: Is not checked the relayer has complete freedom.
            #[::anchor_lang::prelude::account(mut)]
            pub relayer_recipient: ::anchor_lang::prelude::UncheckedAccount<'info>,
            /// CHECK: Is checked when it is used during spl withdrawals.
            #[::anchor_lang::prelude::account(
                mut,
                seeds=[::merkle_tree_program::utils::constants::TOKEN_AUTHORITY_SEED],
                bump,
                seeds::program=::merkle_tree_program::program::MerkleTreeProgram::id()
            )]
            pub token_authority: ::anchor_lang::prelude::AccountInfo<'info>,
            /// Verifier config pda which needs ot exist Is not checked the relayer has complete freedom.
            /// CHECK: Is the same as in integrity hash.
            #[::anchor_lang::prelude::account(
                mut,
                seeds=[program_id.key().to_bytes().as_ref()],
                bump,
                seeds::program=::merkle_tree_program::program::MerkleTreeProgram::id()
            )]
            pub registered_verifier_pda: ::anchor_lang::prelude::Account<
                'info,
                ::merkle_tree_program::config_accounts::register_verifier::RegisteredVerifier
            >,
        }
        #semi_token
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
        let res = light_verifier_accounts(
            parse_quote! {},
            parse_quote! {
                struct Accounts {
                    pub verifier_state: Signer<'info>,
                }
            },
        )
        .expect("Failed to expand light_verifier_accounts")
        .to_string();

        println!("{}", res);

        assert!(res.contains("struct Accounts {"));
        assert!(res.contains("pub verifier_state : Signer < 'info > ,"));
        assert!(res.contains(
            "pub program_merkle_tree : :: anchor_lang :: prelude :: Program < 'info \
                              , :: merkle_tree_program :: program :: MerkleTreeProgram > ,"
        ));
        assert!(res.contains("# [:: anchor_lang :: prelude :: account (mut)]"));
        assert!(res.contains("pub merkle_tree : :: anchor_lang :: prelude :: AccountLoader < 'info \
                              , :: merkle_tree_program :: poseidon_merkle_tree :: state :: MerkleTree >"));
        assert!(res.contains(
            "# [:: anchor_lang :: prelude :: account (mut , seeds = [:: \
                              merkle_tree_program :: program :: MerkleTreeProgram :: id () . \
                              to_bytes () . as_ref ()] , bump)]"
        ));
        assert!(res
            .contains("pub authority : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"));
        assert!(res.contains(
            "pub token_program : :: anchor_lang :: prelude :: Program < 'info , :: anchor_lang :: \
                              prelude :: Token > ,"
        ));
        assert!(
            res.contains("pub sender : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,")
        );
        assert!(res
            .contains("pub recipient : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"));
        assert!(res.contains(
            "pub sender_fee : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"
        ));
        assert!(res.contains(
            "pub recipient_fee : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"
        ));
        assert!(res.contains(
            "pub relayer_recipient : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"
        ));
        assert!(res.contains(
            "# [:: anchor_lang :: prelude :: account (mut , seeds = [:: \
                              merkle_tree_program :: utils :: constants :: TOKEN_AUTHORITY_SEED] , \
                              bump , seeds :: program = :: merkle_tree_program :: program :: \
                              MerkleTreeProgram :: id ())]"
        ));
        assert!(res.contains(
            "pub token_authority : :: anchor_lang :: prelude :: AccountInfo < 'info > ,"
        ));
        assert!(res.contains(
            "# [:: anchor_lang :: prelude :: account (mut , seeds = [program_id . \
                              key () . to_bytes () . as_ref ()] , bump , seeds :: program = :: \
                              merkle_tree_program :: program :: MerkleTreeProgram :: id ())]"
        ));
        assert!(res.contains(
            "pub registered_verifier_pda : :: anchor_lang :: prelude :: Account < 'info , \
                              :: merkle_tree_program :: config_accounts :: register_verifier :: \
                              RegisteredVerifier > ,"
        ));
    }

    #[test]
    fn test_light_verifier_accounts_generics() {
        let res = light_verifier_accounts(
            parse_quote! {},
            parse_quote! {
                struct Accounts<T> {
                    pub verifier_state: Signer<'info>,
                }
            },
        )
        .expect("Failed to expand light_verifier_accounts")
        .to_string();

        assert!(res.contains("struct Accounts < T > {"));
        assert!(res.contains("pub verifier_state : Signer < 'info > ,"));
        assert!(res.contains(
            "pub program_merkle_tree : :: anchor_lang :: prelude :: Program < 'info \
                              , :: merkle_tree_program :: program :: MerkleTreeProgram > ,"
        ));
        assert!(res.contains("# [:: anchor_lang :: prelude :: account (mut)]"));
        assert!(res.contains("pub merkle_tree : :: anchor_lang :: prelude :: AccountLoader < 'info \
                              , :: merkle_tree_program :: poseidon_merkle_tree :: state :: MerkleTree >"));
        assert!(res.contains(
            "# [:: anchor_lang :: prelude :: account (mut , seeds = [:: \
                              merkle_tree_program :: program :: MerkleTreeProgram :: id () . \
                              to_bytes () . as_ref ()] , bump)]"
        ));
        assert!(res
            .contains("pub authority : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"));
        assert!(res.contains(
            "pub token_program : :: anchor_lang :: prelude :: Program < 'info , :: anchor_lang :: \
                              prelude :: Token > ,"
        ));
        assert!(
            res.contains("pub sender : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,")
        );
        assert!(res
            .contains("pub recipient : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"));
        assert!(res.contains(
            "pub sender_fee : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"
        ));
        assert!(res.contains(
            "pub recipient_fee : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"
        ));
        assert!(res.contains(
            "pub relayer_recipient : :: anchor_lang :: prelude :: UncheckedAccount < 'info > ,"
        ));
        assert!(res.contains(
            "# [:: anchor_lang :: prelude :: account (mut , seeds = [:: \
                              merkle_tree_program :: utils :: constants :: TOKEN_AUTHORITY_SEED] , \
                              bump , seeds :: program = :: merkle_tree_program :: program :: \
                              MerkleTreeProgram :: id ())]"
        ));
        assert!(res.contains(
            "pub token_authority : :: anchor_lang :: prelude :: AccountInfo < 'info > ,"
        ));
        assert!(res.contains(
            "# [:: anchor_lang :: prelude :: account (mut , seeds = [program_id . \
                              key () . to_bytes () . as_ref ()] , bump , seeds :: program = :: \
                              merkle_tree_program :: program :: MerkleTreeProgram :: id ())]"
        ));
        assert!(res.contains(
            "pub registered_verifier_pda : :: anchor_lang :: prelude :: Account < 'info , \
                              :: merkle_tree_program :: config_accounts :: register_verifier :: \
                              RegisteredVerifier > ,"
        ));
    }
}
