mod client;

use std::collections::HashMap;

use clap::{Parser, Subcommand};
use client::{Credentials, PorkbunClient};

#[derive(Parser)]
#[command(name = "porkbun-cli")]
#[command(about = "A CLI for the Porkbun DNS API")]
#[command(after_help = "EXAMPLES:
    Check domain availability:
        porkbun-cli check example.com coolname.dev

    List DNS records:
        porkbun-cli dns list example.com

    Create an A record for www.example.com pointing to 192.168.1.1:
        porkbun-cli dns create example.com -t A -n www -c 192.168.1.1

    Create a TXT record at the root domain:
        porkbun-cli dns create example.com -t TXT -c \"v=spf1 include:_spf.google.com ~all\"

    Delete a DNS record by ID:
        porkbun-cli dns delete example.com 123456789

    Get SSL certificate (private key only):
        porkbun-cli ssl get example.com -f private-key

    Get pricing for .dev domains:
        porkbun-cli pricing -t dev

    Check domain availability matrix:
        porkbun-cli matrix foo,bar --tlds com,dev,io

AUTHENTICATION:
    Credentials are loaded from mnemon secrets manager:
        mnemon secrets get porkbun-api --field api-key
        mnemon secrets get porkbun-api --field secret-key")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check API connectivity and show your IP
    Ping,
    /// Check if a domain is available for registration
    #[command(after_help = "EXAMPLES:
    Check a single domain:
        porkbun-cli check example.com

    Check multiple domains at once:
        porkbun-cli check coolname.dev mysite.io another.com

OUTPUT:
    Available domains show pricing:
        coolname.dev: AVAILABLE - $12.15 (renewal: $12.15)
    Premium domains are marked:
        rare.io: AVAILABLE [PREMIUM] - $500.00 (renewal: $50.00)
    Taken domains show status only:
        google.com: TAKEN")]
    Check {
        /// Domain(s) to check availability for (e.g., "example.com", "mysite.dev")
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
    /// Check domain availability across prefix × TLD combinations
    #[command(after_help = "EXAMPLES:
    Check multiple prefixes against multiple TLDs:
        porkbun-cli matrix foo,bar,baz --tlds com,dev,io

    Single prefix, multiple TLDs:
        porkbun-cli matrix mysite --tlds com,net,org,io

OUTPUT:
    Shows a grid of availability with pricing:
                  .com        .dev        .io
    foo           $12.15      TAKEN       $39.99
    bar           TAKEN       $15.00      $29.99 [P]")]
    Matrix {
        /// Comma-separated list of domain prefixes to check
        #[arg(required = true, value_delimiter = ',')]
        prefixes: Vec<String>,

        /// Comma-separated list of TLDs to check (without dots)
        #[arg(short, long, required = true, value_delimiter = ',')]
        tlds: Vec<String>,
    },
}

#[derive(Subcommand)]
enum DnsCommands {
    /// List all DNS records for a domain
    #[command(after_help = "EXAMPLE:\n    porkbun-cli dns list example.com")]
    List {
        /// The domain to list records for (e.g., "example.com")
        domain: String,
    },
    /// Create a new DNS record
    #[command(after_help = "EXAMPLES:
    A record for subdomain:
        porkbun-cli dns create example.com -t A -n www -c 192.168.1.1

    A record at root (apex):
        porkbun-cli dns create example.com -t A -c 192.168.1.1

    MX record with priority:
        porkbun-cli dns create example.com -t MX -c mail.example.com -p 10

    TXT record for SPF:
        porkbun-cli dns create example.com -t TXT -c \"v=spf1 include:_spf.google.com ~all\"

    CNAME record:
        porkbun-cli dns create example.com -t CNAME -n blog -c myblog.ghost.io")]
    Create {
        /// The domain to create the record for (e.g., "example.com")
        domain: String,
        /// Record type: A, AAAA, CNAME, MX, TXT, NS, SRV, TLSA, CAA
        #[arg(short = 't', long)]
        r#type: String,
        /// Record content (IP address, hostname, or text value)
        #[arg(short, long)]
        content: String,
        /// Subdomain name, or omit for root/apex record (e.g., "www", "mail", "_dmarc")
        #[arg(short, long)]
        name: Option<String>,
        /// Time-to-live in seconds [default: 600]
        #[arg(long, default_value = "600")]
        ttl: u32,
        /// Priority (required for MX records, lower = higher priority)
        #[arg(short, long)]
        prio: Option<u32>,
    },
    /// Update an existing DNS record
    #[command(after_help = "EXAMPLE:
    First list records to get the ID:
        porkbun-cli dns list example.com

    Then update by ID:
        porkbun-cli dns update example.com 123456789 -t A -c 10.0.0.1")]
    Update {
        /// The domain the record belongs to (e.g., "example.com")
        domain: String,
        /// The record ID to update (from 'dns list' output)
        id: String,
        /// Record type: A, AAAA, CNAME, MX, TXT, NS, SRV, TLSA, CAA
        #[arg(short = 't', long)]
        r#type: String,
        /// New record content (IP address, hostname, or text value)
        #[arg(short, long)]
        content: String,
        /// Subdomain name, or omit for root/apex record
        #[arg(short, long)]
        name: Option<String>,
        /// Time-to-live in seconds
        #[arg(long)]
        ttl: Option<u32>,
        /// Priority (for MX records)
        #[arg(short, long)]
        prio: Option<u32>,
    },
    /// Delete a DNS record
    #[command(after_help = "EXAMPLE:
    First list records to get the ID:
        porkbun-cli dns list example.com

    Then delete by ID:
        porkbun-cli dns delete example.com 123456789")]
    Delete {
        /// The domain the record belongs to (e.g., "example.com")
        domain: String,
        /// The record ID to delete (from 'dns list' output)
        id: String,
    },
}

#[derive(Subcommand)]
enum SslCommands {
    /// Get SSL certificate bundle for a domain
    #[command(after_help = "EXAMPLES:
    Get full certificate bundle:
        porkbun-cli ssl get example.com

    Get just the private key (for server config):
        porkbun-cli ssl get example.com -f private-key

    Get just the certificate chain:
        porkbun-cli ssl get example.com -f chain

NOTE:
    This retrieves the SSL certificate that Porkbun provisions for your domain.
    The domain must be registered with Porkbun and have SSL enabled.")]
    Get {
        /// The domain to get the SSL bundle for (must be registered with Porkbun)
        domain: String,
        /// Output format: full, chain, private-key, public-key
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

/// Result cell for matrix display
enum MatrixCell {
    Available { price: String, is_premium: bool },
    Taken,
    Error(String),
}

impl MatrixCell {
    fn from_check(result: client::DomainCheckResponse) -> Self {
        if result.avail.unwrap_or(false) {
            MatrixCell::Available {
                price: result.price.unwrap_or_else(|| "N/A".to_string()),
                is_premium: result.premium.unwrap_or(false),
            }
        } else {
            MatrixCell::Taken
        }
    }

    fn display(&self) -> String {
        match self {
            MatrixCell::Available { price, is_premium } => {
                if *is_premium {
                    format!("${} [P]", price)
                } else {
                    format!("${}", price)
                }
            }
            MatrixCell::Taken => "TAKEN".to_string(),
            MatrixCell::Error(msg) => format!("ERR: {}", truncate(msg, 8)),
        }
    }
}

fn print_matrix_grid(
    prefixes: &[String],
    tlds: &[String],
    results: &HashMap<String, HashMap<String, MatrixCell>>,
) {
    // Calculate column widths
    let prefix_width = prefixes.iter().map(|p| p.len()).max().unwrap_or(8).max(8);
    let cell_width = 12; // enough for "$1234.56 [P]"

    // Header row
    print!("{:width$}", "", width = prefix_width + 2);
    for tld in tlds {
        print!("{:>width$}", format!(".{}", tld), width = cell_width);
    }
    println!();

    // Data rows
    for prefix in prefixes {
        print!("{:<width$}  ", prefix, width = prefix_width);
        for tld in tlds {
            let cell = results
                .get(prefix)
                .and_then(|m| m.get(tld))
                .map(|c| c.display())
                .unwrap_or_else(|| "???".to_string());
            print!("{:>width$}", cell, width = cell_width);
        }
        println!();
    }
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
            // Porkbun rate limits to 1 check per 10 seconds
            const RATE_LIMIT_WAIT: u64 = 11;

            for (i, domain) in domains.iter().enumerate() {
                // Proactive wait between domains (skip for first domain)
                if i > 0 {
                    eprintln!("Waiting {RATE_LIMIT_WAIT}s for rate limit...");
                    tokio::time::sleep(std::time::Duration::from_secs(RATE_LIMIT_WAIT)).await;
                }

                // Retry loop for rate limiting (reactive wait if we still hit it)
                let result = loop {
                    match client.check_domain(domain).await {
                        Ok(result) => break Ok(result),
                        Err(client::PorkbunError::RateLimited { ttl, message }) => {
                            let wait = ttl + 1; // Add buffer to avoid edge cases
                            eprintln!("{domain}: {message} - waiting {wait}s...");
                            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                            continue;
                        }
                        Err(e) => break Err(e),
                    }
                };

                match result {
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
                println!(
                    "{:<15} {:>12} {:>12} {:>12}",
                    "TLD", "REGISTER", "RENEW", "TRANSFER"
                );
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
        Commands::Matrix { prefixes, tlds } => {
            // Porkbun rate limits to 1 check per 10 seconds
            const RATE_LIMIT_WAIT: u64 = 11;

            // Calculate total checks and estimate time
            let total_checks = prefixes.len() * tlds.len();
            let estimated_seconds = if total_checks > 1 {
                (total_checks - 1) * RATE_LIMIT_WAIT as usize
            } else {
                0
            };
            let estimated_minutes = estimated_seconds / 60;
            let remaining_seconds = estimated_seconds % 60;

            if estimated_minutes > 0 {
                eprintln!(
                    "Checking {} domains (estimated ~{}m {}s)...\n",
                    total_checks, estimated_minutes, remaining_seconds
                );
            } else {
                eprintln!("Checking {} domains...\n", total_checks);
            }

            // Build results matrix (prefix -> tld -> result)
            let mut results: HashMap<String, HashMap<String, MatrixCell>> = HashMap::new();
            let mut check_count = 0;

            for prefix in &prefixes {
                results.insert(prefix.clone(), HashMap::new());

                for tld in &tlds {
                    // Rate limit wait (skip first)
                    if check_count > 0 {
                        eprintln!(
                            "[{}/{}] Waiting {}s...",
                            check_count, total_checks, RATE_LIMIT_WAIT
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(RATE_LIMIT_WAIT)).await;
                    }
                    check_count += 1;

                    let domain = format!("{}.{}", prefix, tld);
                    eprintln!("[{}/{}] Checking {}...", check_count, total_checks, domain);

                    // Check with retry loop
                    let cell = loop {
                        match client.check_domain(&domain).await {
                            Ok(result) => break MatrixCell::from_check(result),
                            Err(client::PorkbunError::RateLimited { ttl, message }) => {
                                eprintln!("  Rate limited: {} - waiting {}s...", message, ttl + 1);
                                tokio::time::sleep(std::time::Duration::from_secs(ttl + 1)).await;
                                continue;
                            }
                            Err(e) => break MatrixCell::Error(e.to_string()),
                        }
                    };

                    results.get_mut(prefix).unwrap().insert(tld.clone(), cell);
                }
            }

            // Print grid
            eprintln!(); // blank line before results
            print_matrix_grid(&prefixes, &tlds, &results);
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
