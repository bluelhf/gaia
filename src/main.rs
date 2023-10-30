mod error;

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, stderr, stdin, stdout, Write};
use clap::{Parser, Subcommand};
use main_error::MainError;
use gaia::{decrypt, encrypt, keystore::{from_secret, to_secret}};
use crate::error::CliError;

#[derive(Parser, Debug)]
#[command(author, version, about = "Encrypt and decrypt files.", long_about = "Gaia is a command-line application for encrypting and decrypting files.")]
struct Args {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Encrypts a file.", long_about = "Encrypts the provided file using a randomly-generated key and writes it to the given output file.")]
    Encrypt {
        #[arg(name = "file path", help = "The file to encrypt, like /home/alice/ILOVEYOU.txt.")]
        file_path: Cow<'static, str>,
        #[arg(name = "output path", long = "output", short = 'o', default_value = "e.out", help = "Output for the encrypted file, like /home/alice/SECRET_LETTER.enc")]
        output: Cow<'static, str>,
        #[arg(name = "secret path", long = "secret", short = 's', default_value = "-", help = "Output for the secret decryption key, like /home/alice/LETTER.key")]
        secret_path: Cow<'static, str>
    },
    #[command(about = "Decrypts a file.", long_about = "Decrypts a file using the given key and writes it to the given output file.")]
    Decrypt {
        #[arg(name = "secret key", help = "The secret key for decryption, like CJLote8FEmo...vBSAD.")]
        secret_key: Cow<'static, str>,
        #[arg(name = "file path", help = "The file to decrypt, like /home/bob/Downloads/SECRET_LETTER.enc.")]
        file_path: Cow<'static, str>,
        #[arg(name = "output path", long = "output", short = 'o', default_value = "d.out", help = "Output for the decrypted file, like /home/bob/MYSTERY_LETTER.txt")]
        output: Cow<'static, str>
    }
}

fn main() -> Result<(), MainError> {
    let args = Args::parse();

    fn input_name(path: &str) -> String {
        if path == "-" { "standard input".to_string() } else { format!("input file '{path}'") }
    }

    fn output_name(path: &str) -> String {
        match path {
            "-" => "standard output".to_string(),
            "^" => "standard error".to_string(),
            _ => format!("output file '{path}'")
        }
    }

    fn open_input(path: &str) -> Result<Box<dyn Read>, io::Error> {
        return Ok(if path == "-" {
            Box::new(stdin())
        } else {
            Box::new(File::open(path)?)
        })
    }

    fn open_output(path: &str) -> Result<Box<dyn Write>, io::Error> {
        return Ok(match path {
            "-" => Box::new(stdout()),
            "^" => Box::new(stderr()),
            _ => Box::new(OpenOptions::new()
                .create(true).write(true).truncate(true).open(path)?)
        })
    }

    match &args.command {
        Commands::Encrypt { file_path: input, output, secret_path } => {
            let input_file = open_input(input).map_err(|e| CliError::OpeningInput(input_name(input), e))?;
            let output_file = open_output(output).map_err(|e| CliError::OpeningOutput(output_name(output), e))?;
            let mut secret_file = open_output(secret_path).map_err(|e| CliError::WritingSecret(output_name(secret_path), e))?;

            let handle = encrypt(input_file, output_file)?;

            let secret = to_secret(&handle).map_err(|e| CliError::InvalidSecret(e))?;
            secret_file.write_all(secret.as_bytes()).map_err(|e| CliError::WritingSecret(output_name(secret_path), e))?;
            secret_file.write(&[10])?;

            Ok(())
        }
        Commands::Decrypt { secret_key, file_path: input, output } => {
            let input_file = open_input(input).map_err(|e| CliError::OpeningInput(input_name(input), e))?;
            let output_file = open_output(output).map_err(|e| CliError::OpeningOutput(output_name(output), e))?;

            Ok(decrypt(input_file, &from_secret(secret_key.as_ref())
                .map_err(|e| CliError::InvalidSecret(e))?, output_file)?)
        }
    }
}
