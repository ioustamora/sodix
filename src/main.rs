use clap::{Parser, Subcommand};
use dryoc::classic::crypto_box::{crypto_box_easy, crypto_box_open_easy};
use dryoc::classic::crypto_sign::{crypto_sign_detached, crypto_sign_verify_detached};
use dryoc::keypair::StackKeyPair;
use dryoc::sign::SigningKeyPair;
use dryoc::types::StackByteArray;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::{self, Write};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Parser)]
#[command(name = "sodix", about = "sodix - libsodium compatible cli tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enable verbose output for debugging
    #[arg(long, short = 'v', global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a message or file
    #[command(visible_alias = "s")]
    Sign {
        input: String,
        #[arg(long, short = 'k')]
        key: Option<PathBuf>,
        #[arg(long, short = 'f')]
        file: bool,
    },
    /// Verify a signature
    #[command(visible_alias = "c")]
    Check {
        input: String,
        signature: String,
        #[arg(long, short = 'k')]
        key: Option<PathBuf>,
        #[arg(long, short = 'f')]
        file: bool,
    },
    /// Encrypt a message or file
    #[command(visible_alias = "e")] 
    Encrypt {
        input: String,
        #[arg(long, short = 'k')]
        pubkey: Option<String>,  // Receiver's public key in hex
        #[arg(long, short = 's')]
        seckey: Option<String>,  // Sender's secret key in hex
        #[arg(long, short = 'f')]
        file: bool,
    },
    /// Decrypt a message or file
    #[command(visible_alias = "d")]
    Decrypt {
        input: String,
        #[arg(long, short = 'k')]
        pubkey: Option<String>,  // Sender's public key in hex
        #[arg(long, short = 's')]
        seckey: Option<String>,  // Receiver's secret key in hex
        #[arg(long, short = 'f')]
        file: bool,
    },
    /// Generate new keypairs
    #[command(visible_alias = "g")]
    Generate {
        #[arg(long, short = 'k')]
        key: Option<PathBuf>,
    },
    /// Print keys
    #[command(visible_alias = "p")]
    Print {
        #[arg(long, short = 'k')]
        key: Option<PathBuf>,
    },
}
fn get_default_key_path(key_type: &str) -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("{}.key", key_type))
}

fn load_key(path: &Path, expected_size: usize) -> Result<Vec<u8>, String> {
    let key_hex = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read key from {}: {}", path.display(), e))?;
    let key_bytes = hex::decode(key_hex.trim())
        .map_err(|e| format!("Invalid hex in key file {}: {}", path.display(), e))?;
    if key_bytes.len() != expected_size {
        return Err(format!(
            "Key size mismatch for {}: expected {} bytes, got {}",
            path.display(),
            expected_size,
            key_bytes.len()
        ));
    }
    Ok(key_bytes)
}

fn load_or_generate_signing_key(path: &Path, is_secret: bool, verbose: bool) -> Result<Vec<u8>, String> {
    if path.exists() {
        let expected_size = if is_secret { 64 } else { 32 };
        load_key(path, expected_size)
    } else {
        let keypair: SigningKeyPair<StackByteArray<32>, StackByteArray<64>> = SigningKeyPair::gen();
        let dir = path.parent().unwrap();
        let public_key_path = dir.join("sign_public.key");
        let secret_key_path = dir.join("sign_secret.key");
        fs::write(&public_key_path, hex::encode(&keypair.public_key))
            .map_err(|e| format!("Failed to write signing public key to {}: {}", public_key_path.display(), e))?;
        fs::write(&secret_key_path, hex::encode(&keypair.secret_key))
            .map_err(|e| format!("Failed to write signing secret key to {}: {}", secret_key_path.display(), e))?;
        if verbose {
            println!(
                "Generated signing keys at: {} and {}",
                public_key_path.display(),
                secret_key_path.display()
            );
        }
        Ok(if is_secret {
            keypair.secret_key.to_vec()
        } else {
            keypair.public_key.to_vec()
        })
    }
}

fn load_or_generate_encryption_key(path: &Path, is_secret: bool, verbose: bool) -> Result<Vec<u8>, String> {
    if path.exists() {
        load_key(path, 32)
    } else {
        let keypair = StackKeyPair::gen();
        let dir = path.parent().unwrap();
        let public_key_path = dir.join("enc_public.key");
        let secret_key_path = dir.join("enc_secret.key");
        fs::write(&public_key_path, hex::encode(&keypair.public_key))
            .map_err(|e| format!("Failed to write encryption public key to {}: {}", public_key_path.display(), e))?;
        fs::write(&secret_key_path, hex::encode(&keypair.secret_key))
            .map_err(|e| format!("Failed to write encryption secret key to {}: {}", secret_key_path.display(), e))?;
        if verbose {
            println!(
                "Generated encryption keys at: {} and {}",
                public_key_path.display(),
                secret_key_path.display()
            );
        }
        Ok(if is_secret {
            keypair.secret_key.to_vec()
        } else {
            keypair.public_key.to_vec()
        })
    }
}

fn generate_keys(dir: &Path, verbose: bool) -> Result<(), String> {
    // Create directory if it doesn't exist
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create directory {}: {}", dir.display(), e))?;

    let sign_keypair: SigningKeyPair<StackByteArray<32>, StackByteArray<64>> = SigningKeyPair::gen();
    let sign_public_key_path = dir.join("sign_public.key");
    let sign_secret_key_path = dir.join("sign_secret.key");
    fs::write(&sign_public_key_path, hex::encode(&sign_keypair.public_key))
        .map_err(|e| format!("Failed to write signing public key to {}: {}", sign_public_key_path.display(), e))?;
    fs::write(&sign_secret_key_path, hex::encode(&sign_keypair.secret_key))
        .map_err(|e| format!("Failed to write signing secret key to {}: {}", sign_secret_key_path.display(), e))?;

    let enc_keypair = StackKeyPair::gen();
    let enc_public_key_path = dir.join("enc_public.key");
    let enc_secret_key_path = dir.join("enc_secret.key");
    fs::write(&enc_public_key_path, hex::encode(&enc_keypair.public_key))
        .map_err(|e| format!("Failed to write encryption public key to {}: {}", enc_public_key_path.display(), e))?;
    fs::write(&enc_secret_key_path, hex::encode(&enc_keypair.secret_key))
        .map_err(|e| format!("Failed to write encryption secret key to {}: {}", enc_secret_key_path.display(), e))?;

    if verbose {
        println!(
            "Generated keys at: {}, {}, {}, and {}",
            sign_public_key_path.display(),
            sign_secret_key_path.display(),
            enc_public_key_path.display(),
            enc_secret_key_path.display()
        );
    }
    Ok(())
}

fn print_keys(dir: &Path, verbose: bool) -> Result<(), String> {
    // Create directory if it doesn't exist
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create directory {}: {}", dir.display(), e))?;

    // Generate both key pairs if any key file is missing
    let sign_public_key_path = dir.join("sign_public.key");
    let sign_secret_key_path = dir.join("sign_secret.key");
    let enc_public_key_path = dir.join("enc_public.key");
    let enc_secret_key_path = dir.join("enc_secret.key");

    if !sign_public_key_path.exists() || !sign_secret_key_path.exists() 
        || !enc_public_key_path.exists() || !enc_secret_key_path.exists() {
        if verbose {
            println!("Some keys missing, generating new keypairs...");
        }
        generate_keys(dir, verbose)?;
    }

    let sign_pk = load_key(&sign_public_key_path, 32).map(|k| hex::encode(k))?;
    let sign_sk = load_key(&sign_secret_key_path, 64).map(|k| hex::encode(k))?;
    let enc_pk = load_key(&enc_public_key_path, 32).map(|k| hex::encode(k))?;
    let enc_sk = load_key(&enc_secret_key_path, 32).map(|k| hex::encode(k))?;

    if verbose {
        println!("Signing Public Key (sign_public.key): {}", sign_pk);
        println!("Signing Secret Key (sign_secret.key): {}", sign_sk);
        println!("Encryption Public Key (enc_public.key): {}", enc_pk);
        println!("Encryption Secret Key (enc_secret.key): {}", enc_sk);
    } else {
        println!("{}", sign_pk); // Line 1: Signing Public Key
        println!("{}", sign_sk); // Line 2: Signing Secret Key
        println!("{}", enc_pk);  // Line 3: Encryption Public Key
        println!("{}", enc_sk);  // Line 4: Encryption Secret Key
    }
    Ok(())
}

fn parse_hex_key(hex_key: &str) -> Result<[u8; 32], String> {
    let key_vec = hex::decode(hex_key)
        .map_err(|e| format!("Invalid hex key: {}", e))?;
    key_vec.try_into()
        .map_err(|_| "Public key must be 32 bytes".to_string())
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let verbose = cli.verbose;

    match cli.command {
        Commands::Sign { input, key, file } => {
            let secret_key_path = key.unwrap_or_else(|| get_default_key_path("sign_secret"));
            let sk = load_or_generate_signing_key(&secret_key_path, true, verbose)?;
            let data = if file {
                fs::read(&input).map_err(|e| format!("Failed to read input file {}: {}", input, e))
            } else {
                Ok(input.into_bytes())
            }?;
            let mut signature = [0u8; 64];
            crypto_sign_detached(&mut signature, &data, sk.as_slice().try_into().unwrap())
                .map_err(|e| format!("Error signing data: {}", e))?;
            println!("{}", hex::encode(&signature));
        }

        Commands::Check { input, signature, key, file } => {
            let public_key_path = key.unwrap_or_else(|| get_default_key_path("sign_public"));
            let pk = load_or_generate_signing_key(&public_key_path, false, verbose)?;
            let data = if file {
                fs::read(&input).map_err(|e| format!("Failed to read input file {}: {}", input, e))
            } else {
                Ok(input.into_bytes())
            }?;
            let sig = hex::decode(&signature).map_err(|e| format!("Invalid hex signature: {}", e))?;
            let result = crypto_sign_verify_detached(
                sig.as_slice().try_into().map_err(|_| "Signature must be 64 bytes")?,
                &data,
                pk.as_slice().try_into().unwrap(),
            );
            match result {
                Ok(_) => println!("valid"),
                Err(e) => {
                    if verbose {
                        eprintln!("Signature verification failed: {}", e);
                    }
                    println!("invalid");
                }
            }
        }

        Commands::Encrypt { input, pubkey, seckey, file } => {
            let pk = match pubkey {
                Some(hex_key) => parse_hex_key(&hex_key)?,
                None => {
                    let public_key_path = get_default_key_path("enc_public");
                    let pk_vec = load_or_generate_encryption_key(&public_key_path, false, verbose)?;
                    pk_vec.try_into().map_err(|_| "Public key must be 32 bytes")?
                }
            };
            
            let sk = match seckey {
                Some(hex_key) => parse_hex_key(&hex_key)?,
                None => {
                    let secret_key_path = get_default_key_path("enc_secret");
                    let sk_vec = load_or_generate_encryption_key(&secret_key_path, true, verbose)?;
                    sk_vec.try_into().map_err(|_| "Secret key must be 32 bytes")?
                }
            };

            let data = if file {
                fs::read(&input).map_err(|e| format!("Failed to read input file {}: {}", input, e))
            } else {
                Ok(input.clone().into_bytes())
            }?;

            let mut nonce = [0u8; 24];
            let mut rng = StdRng::seed_from_u64(42); // Seed with a u64 value
            rng.fill(&mut nonce);

            let mut ciphertext = vec![0u8; data.len() + 16];
            crypto_box_easy(&mut ciphertext, &data, &nonce, &pk, &sk)
                .map_err(|e| format!("Error encrypting data: {}", e))?;

            let mut combined = Vec::new();
            combined.extend_from_slice(&nonce);
            combined.extend_from_slice(&ciphertext);
            let combined_hex = hex::encode(&combined);

            if file {
                let output_file = format!("{}.x", input);
                fs::write(&output_file, &combined_hex)
                    .map_err(|e| format!("Failed to write encrypted file {}: {}", output_file, e))?;
                if verbose {
                    println!("Encrypted file saved to: {}", output_file);
                }
            } else {
                println!("{}", combined_hex);
            }
        }

        Commands::Decrypt { input, pubkey, seckey, file } => {
            let pk = match pubkey {
                Some(hex_key) => parse_hex_key(&hex_key)?,
                None => {
                    let public_key_path = get_default_key_path("enc_public");
                    let pk_vec = load_or_generate_encryption_key(&public_key_path, false, verbose)?;
                    pk_vec.try_into().map_err(|_| "Public key must be 32 bytes")?
                }
            };

            let sk = match seckey {
                Some(hex_key) => parse_hex_key(&hex_key)?,
                None => {
                    let secret_key_path = get_default_key_path("enc_secret");
                    let sk_vec = load_or_generate_encryption_key(&secret_key_path, true, verbose)?;
                    sk_vec.try_into().map_err(|_| "Secret key must be 32 bytes")?
                }
            };
            
            let (combined, output_path) = if file {
                let encrypted_file = if input.ends_with(".x") { input.clone() } else { format!("{}.x", input) };
                let output_file = if encrypted_file.ends_with(".x") {
                    encrypted_file[..encrypted_file.len()-2].to_string()
                } else {
                    encrypted_file.clone()
                };
                (
                    hex::decode(fs::read_to_string(&encrypted_file)
                        .map_err(|e| format!("Failed to read encrypted file {}: {}", encrypted_file, e))?)
                        .map_err(|e| format!("Invalid hex in file {}: {}", encrypted_file, e))?,
                    Some(output_file)
                )
            } else {
                (hex::decode(&input).map_err(|e| format!("Invalid hex input: {}", e))?, None)
            };

            if combined.len() < 24 + 16 {
                return Err("Input too short; must contain nonce and ciphertext".to_string());
            }
            let nonce: [u8; 24] = combined[..24].try_into().unwrap();
            let ciphertext = &combined[24..];
            let mut plaintext = vec![0u8; ciphertext.len() - 16];
            crypto_box_open_easy(&mut plaintext, ciphertext, &nonce, &pk, &sk)
                .map_err(|e| format!("Error decrypting data: {}", e))?;

            if let Some(output_file) = output_path {
                fs::write(&output_file, &plaintext)
                    .map_err(|e| format!("Failed to write decrypted file {}: {}", output_file, e))?;
                if verbose {
                    println!("Decrypted file saved to: {}", output_file);
                }
            } else {
                io::stdout()
                    .write_all(&plaintext)
                    .map_err(|e| format!("Failed to write decrypted data: {}", e))?;
                io::stdout().flush().map_err(|e| format!("Failed to flush output: {}", e))?;
            }
        }

        Commands::Generate { key } => {
            let dir = key.unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .to_path_buf()
            });
            generate_keys(&dir, verbose)?;
            if !verbose {
                println!("Keys generated successfully");
            }
        }

        Commands::Print { key } => {
            let dir = key.unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .to_path_buf()
            });
            print_keys(&dir, verbose)?;
        }
    }
    Ok(())
}