use dolphi_encryption_evaluation::{initialized, metadata};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut key = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(key.as_mut()).map_err(|_| "OS randomness unavailable")?;
    let database = initialized(&directory.path().join("evaluation.db"), &key)?;
    println!("{}", serde_json::to_string_pretty(&metadata(&database)?)?);
    Ok(())
}
