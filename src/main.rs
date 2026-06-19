mod client;

use std::collections::HashMap;
use std::collections::HashSet;

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

    List all owned domains:
        porkbun-cli list

    List domains as JSON:
        porkbun-cli list --json

    Show details for a single domain:
        porkbun-cli info example.com

    Show single-domain details as JSON:
        porkbun-cli info example.com --json

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
    bar           TAKEN       $15.00      $29.99 [P]
    coreyja       OWNED       $15.00      $39.99")]
    Matrix {
        /// Comma-separated list of domain prefixes to check
        #[arg(required = true, value_delimiter = ',')]
        prefixes: Vec<String>,

        /// Comma-separated list of TLDs to check (without dots)
        #[arg(short, long, required = true, value_delimiter = ',')]
        tlds: Vec<String>,
    },
    /// List all domains in your Porkbun account
    #[command(alias = "ls")]
    #[command(after_help = "EXAMPLES:
    Show owned domains as a table:
        porkbun-cli list

    Short alias:
        porkbun-cli ls

    Emit raw JSON for scripting:
        porkbun-cli list --json

    Include domain labels:
        porkbun-cli list --labels")]
    List {
        /// Output as JSON instead of a table
        #[arg(long)]
        json: bool,
        /// Include domain labels in the output
        #[arg(long)]
        labels: bool,
    },
    /// Show detailed info for a single owned domain
    #[command(after_help = "EXAMPLES:
    Show summary for a domain you own:
        porkbun-cli info coreyja.com

    Emit JSON for scripting:
        porkbun-cli info coreyja.com --json")]
    Info {
        /// The domain to show info for (must be in your Porkbun account)
        #[arg(required = true)]
        domain: String,
        /// Output as JSON instead of formatted text
        #[arg(long)]
        json: bool,
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
    Owned,
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
            MatrixCell::Owned => "OWNED".to_string(),
            MatrixCell::Error(msg) => format!("ERR: {}", truncate(msg, 8)),
        }
    }
}

/// Build a set of lowercased full domain names from a list of owned domains.
///
/// Used by the matrix subcommand to short-circuit per-cell availability
/// checks when the user already owns the domain.
fn build_owned_set(domains: &[client::Domain]) -> HashSet<String> {
    domains.iter().map(|d| d.domain.to_lowercase()).collect()
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

            // Fetch owned domains once. include_labels=false (we only need the names).
            eprintln!("Fetching owned domains...");
            let owned_domains = client.list_domains(false).await?;
            let owned_set = build_owned_set(&owned_domains);

            // Compute how many cells will actually require an API check.
            let total_cells = prefixes.len() * tlds.len();
            let mut owned_cells = 0usize;
            for prefix in &prefixes {
                for tld in &tlds {
                    let candidate = format!("{}.{}", prefix, tld).to_lowercase();
                    if owned_set.contains(&candidate) {
                        owned_cells += 1;
                    }
                }
            }
            let api_checks = total_cells - owned_cells;

            // Estimate based on actual API checks, not total cells.
            let estimated_seconds = api_checks.saturating_sub(1) * RATE_LIMIT_WAIT as usize;
            let estimated_minutes = estimated_seconds / 60;
            let remaining_seconds = estimated_seconds % 60;

            if owned_cells > 0 {
                eprintln!(
                    "Checking {} domains ({} already owned, skipped)...",
                    total_cells, owned_cells
                );
            } else {
                eprintln!("Checking {} domains...", total_cells);
            }
            if estimated_minutes > 0 {
                eprintln!(
                    "Estimated ~{}m {}s for API checks.\n",
                    estimated_minutes, remaining_seconds
                );
            } else if estimated_seconds > 0 {
                eprintln!("Estimated ~{}s for API checks.\n", estimated_seconds);
            } else {
                eprintln!();
            }

            // Build results matrix (prefix -> tld -> result)
            let mut results: HashMap<String, HashMap<String, MatrixCell>> = HashMap::new();
            let mut api_check_count = 0usize;

            for prefix in &prefixes {
                results.insert(prefix.clone(), HashMap::new());

                for tld in &tlds {
                    let domain = format!("{}.{}", prefix, tld);

                    // Short-circuit owned cells: no API call, no rate-limit wait.
                    if owned_set.contains(&domain.to_lowercase()) {
                        eprintln!("[owned] {}", domain);
                        results
                            .get_mut(prefix)
                            .unwrap()
                            .insert(tld.clone(), MatrixCell::Owned);
                        continue;
                    }

                    // Rate limit wait (skip before the first actual API call).
                    if api_check_count > 0 {
                        eprintln!(
                            "[{}/{}] Waiting {}s...",
                            api_check_count, api_checks, RATE_LIMIT_WAIT
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(RATE_LIMIT_WAIT)).await;
                    }
                    api_check_count += 1;

                    eprintln!(
                        "[{}/{}] Checking {}...",
                        api_check_count, api_checks, domain
                    );

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
        Commands::List { json, labels } => {
            let mut domains = client.list_domains(labels).await?;
            domains.sort_by_key(|d| d.domain.to_lowercase());

            if json {
                let out = serde_json::to_string_pretty(&domains).map_err(|e| {
                    client::PorkbunError::Api(format!("JSON serialization failed: {e}"))
                })?;
                println!("{out}");
            } else if domains.is_empty() {
                println!("No domains found in account");
            } else {
                print_domain_table(&domains, labels);
            }
        }
        Commands::Info { domain, json } => {
            let domains = client.list_domains(true).await?;
            let domain_lc = domain.to_lowercase();
            let entry = domains
                .into_iter()
                .find(|d| d.domain.to_lowercase() == domain_lc)
                .ok_or_else(|| client::PorkbunError::DomainNotFound(domain.clone()))?;

            let nameservers = client.get_ns(&entry.domain).await?;

            if json {
                print_domain_info_json(&entry, &nameservers)?;
            } else {
                print_domain_info(&entry, &nameservers);
            }
        }
    }

    Ok(())
}

fn print_domain_table(domains: &[client::Domain], show_labels: bool) {
    let domain_w = domains
        .iter()
        .map(|d| d.domain.len())
        .max()
        .unwrap_or(20)
        .max(20);
    let status_w = 10;
    let expire_w = 20;
    let renew_w = 10;
    let priv_w = 10;

    if show_labels {
        println!(
            "{:<dw$} {:<sw$} {:<ew$} {:<rw$} {:<pw$} LABELS",
            "DOMAIN",
            "STATUS",
            "EXPIRES",
            "AUTORENEW",
            "WHOIS",
            dw = domain_w,
            sw = status_w,
            ew = expire_w,
            rw = renew_w,
            pw = priv_w
        );
    } else {
        println!(
            "{:<dw$} {:<sw$} {:<ew$} {:<rw$} {:<pw$}",
            "DOMAIN",
            "STATUS",
            "EXPIRES",
            "AUTORENEW",
            "WHOIS",
            dw = domain_w,
            sw = status_w,
            ew = expire_w,
            rw = renew_w,
            pw = priv_w
        );
    }
    let sep_len =
        domain_w + status_w + expire_w + renew_w + priv_w + 4 + if show_labels { 16 } else { 0 };
    println!("{}", "-".repeat(sep_len));

    for d in domains {
        let auto_renew = format_yn(&d.auto_renew);
        let whois = format_yn(&d.whois_privacy);

        if show_labels {
            let labels_str = d
                .labels
                .as_ref()
                .map(|ls| {
                    ls.iter()
                        .map(|l| l.title.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            println!(
                "{:<dw$} {:<sw$} {:<ew$} {:<rw$} {:<pw$} {}",
                d.domain,
                d.status,
                d.expire_date,
                auto_renew,
                whois,
                labels_str,
                dw = domain_w,
                sw = status_w,
                ew = expire_w,
                rw = renew_w,
                pw = priv_w
            );
        } else {
            println!(
                "{:<dw$} {:<sw$} {:<ew$} {:<rw$} {:<pw$}",
                d.domain,
                d.status,
                d.expire_date,
                auto_renew,
                whois,
                dw = domain_w,
                sw = status_w,
                ew = expire_w,
                rw = renew_w,
                pw = priv_w
            );
        }
    }
}

fn print_domain_info(d: &client::Domain, nameservers: &[String]) {
    const LABEL_WIDTH: usize = 16;

    println!("Domain: {}", d.domain);
    println!("  {:<w$}{}", "Status:", d.status, w = LABEL_WIDTH);

    let expires = d
        .expire_date
        .split_whitespace()
        .next()
        .unwrap_or(&d.expire_date);
    println!("  {:<w$}{}", "Expires:", expires, w = LABEL_WIDTH);

    println!(
        "  {:<w$}{}",
        "Auto-Renew:",
        format_yn(&d.auto_renew),
        w = LABEL_WIDTH
    );
    println!(
        "  {:<w$}{}",
        "Whois Privacy:",
        format_yn(&d.whois_privacy),
        w = LABEL_WIDTH
    );
    println!(
        "  {:<w$}{}",
        "Security Lock:",
        format_yn(&d.security_lock),
        w = LABEL_WIDTH
    );

    if let Some(labels) = d.labels.as_ref()
        && !labels.is_empty()
    {
        let joined = labels
            .iter()
            .map(|l| l.title.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {:<w$}{}", "Labels:", joined, w = LABEL_WIDTH);
    }

    if nameservers.is_empty() {
        println!("  {:<w$}(none)", "Nameservers:", w = LABEL_WIDTH);
    } else {
        println!("  Nameservers:");
        for ns in nameservers {
            println!("    - {ns}");
        }
    }
}

fn print_domain_info_json(
    d: &client::Domain,
    nameservers: &[String],
) -> Result<(), client::PorkbunError> {
    #[derive(serde::Serialize)]
    struct DomainInfoJson<'a> {
        #[serde(flatten)]
        domain: &'a client::Domain,
        nameservers: &'a [String],
    }

    let payload = DomainInfoJson {
        domain: d,
        nameservers,
    };

    let out = serde_json::to_string_pretty(&payload)
        .map_err(|e| client::PorkbunError::Api(format!("JSON serialization failed: {e}")))?;
    println!("{out}");
    Ok(())
}

/// Render a `serde_json::Value` that may be a string ("1"/"0"/"yes"/"no"),
/// integer (1/0), or bool — into a human-readable yes/no.
///
/// Returns `"?"` for `Null` or unexpected variants.
fn format_yn(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::String(s) => match s.as_str() {
            "1" | "yes" | "true" => "yes",
            "0" | "no" | "false" => "no",
            _ => "?",
        },
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(1) => "yes",
            Some(0) => "no",
            _ => "?",
        },
        serde_json::Value::Bool(b) => {
            if *b {
                "yes"
            } else {
                "no"
            }
        }
        _ => "?",
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_domain(name: &str) -> client::Domain {
        // Domain has serde_json::Value boolean fields with no Default — construct via serde_json.
        serde_json::from_value(serde_json::json!({
            "domain": name,
            "status": "ACTIVE",
            "tld": name.rsplit('.').next().unwrap_or(""),
            "createDate": "2020-01-01 00:00:00",
            "expireDate": "2030-01-01 00:00:00",
            "securityLock": "0",
            "whoisPrivacy": "1",
            "autoRenew": "1",
            "notLocal": "0"
        }))
        .expect("fake domain JSON should deserialize")
    }

    #[test]
    fn matrix_cell_owned_displays_as_owned() {
        assert_eq!(MatrixCell::Owned.display(), "OWNED");
    }

    #[test]
    fn matrix_cell_taken_unchanged() {
        assert_eq!(MatrixCell::Taken.display(), "TAKEN");
    }

    #[test]
    fn matrix_cell_available_unchanged() {
        let cell = MatrixCell::Available {
            price: "12.15".to_string(),
            is_premium: false,
        };
        assert_eq!(cell.display(), "$12.15");
    }

    #[test]
    fn matrix_cell_available_premium_unchanged() {
        let cell = MatrixCell::Available {
            price: "500.00".to_string(),
            is_premium: true,
        };
        assert_eq!(cell.display(), "$500.00 [P]");
    }

    #[test]
    fn build_owned_set_lowercases_names() {
        let domains = vec![fake_domain("CoreyJa.COM"), fake_domain("Example.dev")];
        let set = build_owned_set(&domains);
        assert!(set.contains("coreyja.com"));
        assert!(set.contains("example.dev"));
        assert!(!set.contains("CoreyJa.COM"));
    }

    #[test]
    fn build_owned_set_empty_input() {
        let set = build_owned_set(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn owned_lookup_matches_case_insensitively() {
        let domains = vec![fake_domain("coreyja.com")];
        let set = build_owned_set(&domains);
        // Caller lowercases the candidate before lookup.
        let candidate = format!("{}.{}", "CoreyJa", "COM").to_lowercase();
        assert!(set.contains(&candidate));
    }

    #[test]
    fn owned_lookup_miss_for_unowned() {
        let domains = vec![fake_domain("coreyja.com")];
        let set = build_owned_set(&domains);
        let candidate = format!("{}.{}", "coreyja", "io");
        assert!(!set.contains(&candidate));
    }
}
