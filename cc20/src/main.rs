use chacha20::ChaCha20;
use crypto::{hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha256};
use getopts::Options;
use rand_core::{OsRng, RngCore};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::{env, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this message");
    opts.optflag(
        "d",
        "decrypt",
        "switch to decryption mode (default is encryption)",
    );
    let matches = opts.parse(&args[1..]).unwrap();
    if matches.opt_present("h") {
        print_help(&args[0], opts);
    }
    if matches.free.is_empty() {
        panic!("No password specified");
    }
    let mut input: Box<dyn Read> = if matches.free.len() > 1 {
        Box::new(BufReader::new(File::open(&matches.free[1]).unwrap()))
    } else {
        Box::new(BufReader::new(std::io::stdin()))
    };
    let mut output: Box<dyn Write> = if matches.free.len() > 2 {
        Box::new(BufWriter::new(File::open(&matches.free[2]).unwrap()))
    } else {
        Box::new(BufWriter::new(std::io::stdout()))
    };
    let password = &matches.free[0];
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    if matches.opt_present("d") {
        input.read(&mut salt).unwrap();
        input.read(&mut nonce).unwrap();
    } else {
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        output.write(&mut salt).unwrap();
        output.write(&mut nonce).unwrap();
    }
    let key = key_from_password(password, &salt);
    let mut chacha20 = ChaCha20::new(&key, &nonce);
    internal_loop(&mut chacha20, &mut input, &mut output).unwrap();
}

fn print_help(program_name: &str, opts: Options) -> ! {
    let brief = format!(
        "Usage: {} [options] password [input] [output]",
        program_name
    );
    print!("{}", opts.usage(&brief));
    process::exit(0);
}

fn key_from_password(pwd: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2(
        &mut Hmac::new(Sha256::new(), salt),
        pwd.as_bytes(),
        2000,
        &mut key,
    );
    key
}

fn internal_loop<T: Read, U: Write>(
    _cipher: &mut ChaCha20,
    _input: &mut T,
    _output: &mut U,
) -> Result<(), std::io::Error> {
    Ok(())
}
