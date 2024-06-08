mod error;

use clap::Parser;

use crate::error::AppError;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    port: u16,
}



#[tokio::main]
async fn main()  -> Result<(),AppError>{
    let _config = Config::parse();

    Ok(())
}
