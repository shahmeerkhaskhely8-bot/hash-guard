use std::error::Error;
use std::process;

fn main() {
    let exit_code = match hash_guard::cli::run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");

            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }

            1
        }
    };

    process::exit(exit_code);
}
