use proc_macro::TokenStream;
use syn::parse_macro_input;

mod expand;

/// Converts a base58 encoded public key into a byte array.
#[proc_macro]
pub fn pubkey(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as expand::PubkeyArgs);
    expand::pubkey(args)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
