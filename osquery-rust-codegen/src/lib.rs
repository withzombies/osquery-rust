use proc_macro::TokenStream;

use std::str::FromStr;

/// Defines a CLI for an osquery-rust based extension which is compliant to osquery interface.
#[proc_macro_attribute]
pub fn args(_attr: TokenStream, input: TokenStream) -> TokenStream {
    //todo: error handling!
    let mut output = TokenStream::from_str(include_str!("cli.rs")).unwrap();
    output.extend(input);
    output
}
