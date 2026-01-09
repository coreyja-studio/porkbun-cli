mod client;

use clap::{Parser, Subcommand};
use client::{Credentials, PorkbunClient};

#[derive(Parser)]
#[command(name = "porkbun-cli")]
#[command(about = "A CLI for the Porkbun DNS API")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check API connectivity and show your IP
    Ping,
    /// Check if a domain is available for registration
    Check {
        /// Domain(s) to check availability for (e.g., "example.com")
        #[arg(required = true)]
        domains: Vec<String>,
    },
    /// DNS record management
    Dns {
        #[command(subcommand)]
        command: DnsCommands,
    },
    /// SSL certificate operations
    Ssl {
        #[command(subcommand)]
        command: SslCommands,
    },
    /// Get domain pricing information
    Pricing {
        /// Filter by TLD (e.g., "com", "dev")
        #[arg(short, long)]
        tld: Option<String>,
    },
}

#[derive(Subcommand)]
enum DnsCommands {
    /// List all DNS records for a domain
    List {
        /// The domain to list records for
        domain: String,
    },
    /// Create a new DNS record
    Create {
        /// The domain to create the record for
        domain: String,
        /// Record type (A, AAAA, CNAME, MX, TXT, etc.)
        #[arg(short = 't', long)]
        r#type: String,
        /// Record content (IP address, hostname, text, etc.)
        #[arg(short, long)]
        content: String,
        /// Subdomain name (leave empty for root)
        #[arg(short, long)]
        name: Option<String>,
        /// TTL in seconds (default: 600)
        #[arg(long, default_value = "600")]
        ttl: u32,
        /// Priority (for MX records)
        #[arg(short, long)]
        prio: Option<u32>,
    },
    /// Update an existing DNS record
    Update {
        /// The domain the record belongs to
        domain: String,
        /// The record ID to update
        id: String,
        /// Record type (A, AAAA, CNAME, MX, TXT, etc.)
        #[arg(short = 't', long)]
        r#type: String,
        /// Record content (IP address, hostname, text, etc.)
        #[arg(short, long)]
        content: String,
        /// Subdomain name (leave empty for root)
        #[arg(short, long)]
        name: Option<String>,
        /// TTL in seconds
        #[arg(long)]
        ttl: Option<u32>,
        /// Priority (for MX records)
        #[arg(short, long)]
        prio: Option<u32>,
    },
    /// Delete a DNS record
    Delete {
        /// The domain the record belongs to
        domain: String,
        /// The record ID to delete
        id: String,
    },
}

#[derive(Subcommand)]
enum SslCommands {
    /// Get SSL certificate bundle for a domain
    Get {
        /// The domain to get the SSL bundle for
        domain: String,
        /// Output format
        #[arg(short, long, default_value = "full")]
        format: SslFormat,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum SslFormat {
    /// Show certificate chain, private key, and public key
    Full,
    /// Show only the certificate chain
    Chain,
    /// Show only the private key
    PrivateKey,
    /// Show only the public key
    PublicKey,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), client::PorkbunError> {
    let cli = Cli::parse();

    let credentials = Credentials::from_mnemon()?;
    let client = PorkbunClient::new(credentials);

    match cli.command {
        Commands::Ping => {
            let resp = client.ping().await?;
            println!("API connection successful");
            println!("Your IP: {}", resp.your_ip);
        }
        Commands::Check { domains } => {
            for domain in &domains {
                match client.check_domain(domain).await {
                    Ok(result) => {
                        let available = result.avail.unwrap_or(false);
                        let status = if available { "AVAILABLE" } else { "TAKEN" };

                        if available {
                            let price = result.price.as_deref().unwrap_or("N/A");
                            let renewal = result.renewal_price.as_deref().unwrap_or("N/A");
                            let premium_tag = if result.premium.unwrap_or(false) {
                                " [PREMIUM]"
                            } else {
                                ""
                            };
                            println!(
                                "{domain}: {status}{premium_tag} - ${price} (renewal: ${renewal})"
                            );
                        } else {
                            println!("{domain}: {status}");
                        }
                    }
                    Err(e) => {
                        eprintln!("{domain}: Error - {e}");
                    }
                }
            }
        }
        Commands::Dns { command } => match command {
            DnsCommands::List { domain } => {
                let records = client.list_records(&domain).await?;
                if records.is_empty() {
                    println!("No DNS records found for {domain}");
                } else {
                    println!(
                        "{:<12} {:<8} {:<40} {:<50} {:<8}",
                        "ID", "TYPE", "NAME", "CONTENT", "TTL"
                    );
                    println!("{}", "-".repeat(120));
                    for record in records {
                        println!(
                            "{:<12} {:<8} {:<40} {:<50} {:<8}",
                            record.id,
                            record.record_type,
                            truncate(&record.name, 38),
                            truncate(&record.content, 48),
                            record.ttl
                        );
                    }
                }
            }
            DnsCommands::Create {
                domain,
                r#type,
                content,
                name,
                ttl,
                prio,
            } => {
                let id = client
                    .create_record(&domain, &r#type, &content, name.as_deref(), Some(ttl), prio)
                    .await?;
                println!("Created record with ID: {id}");
            }
            DnsCommands::Update {
                domain,
                id,
                r#type,
                content,
                name,
                ttl,
                prio,
            } => {
                client
                    .update_record(&domain, &id, &r#type, &content, name.as_deref(), ttl, prio)
                    .await?;
                println!("Updated record {id}");
            }
            DnsCommands::Delete { domain, id } => {
                client.delete_record(&domain, &id).await?;
                println!("Deleted record {id}");
            }
        },
        Commands::Ssl { command } => match command {
            SslCommands::Get { domain, format } => {
                let ssl = client.get_ssl(&domain).await?;
                match format {
                    SslFormat::Full => {
                        println!("=== Certificate Chain ===");
                        println!("{}", ssl.certificate_chain);
                        println!("\n=== Private Key ===");
                        println!("{}", ssl.private_key);
                        println!("\n=== Public Key ===");
                        println!("{}", ssl.public_key);
                    }
                    SslFormat::Chain => print!("{}", ssl.certificate_chain),
                    SslFormat::PrivateKey => print!("{}", ssl.private_key),
                    SslFormat::PublicKey => print!("{}", ssl.public_key),
                }
            }
        },
        Commands::Pricing { tld } => {
            let pricing = client.get_pricing().await?;

            if let Some(tld_filter) = tld {
                if let Some(price) = pricing.get(&tld_filter) {
                    println!("Pricing for .{tld_filter}:");
                    println!("  Registration: ${}", price.registration);
                    println!("  Renewal:      ${}", price.renewal);
                    println!("  Transfer:     ${}", price.transfer);
                } else {
                    println!("TLD .{tld_filter} not found");
                }
            } else {
                println!("{:<15} {:>12} {:>12} {:>12}", "TLD", "REGISTER", "RENEW", "TRANSFER");
                println!("{}", "-".repeat(55));

                let mut tlds: Vec<_> = pricing.iter().collect();
                tlds.sort_by_key(|(k, _)| *k);

                for (tld, price) in tlds {
                    println!(
                        ".{:<14} ${:>10} ${:>10} ${:>10}",
                        tld, price.registration, price.renewal, price.transfer
                    );
                }
            }
        }
    }

    Ok(())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}
