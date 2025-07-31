# Void Finder 🔎

Void Finder is an OSINT (Open-Source Intelligence) tool designed to investigate and uncover the potential origin IP address of a website, especially when it's hidden behind a Content Delivery Network (CDN) or a web proxy.

## Features

This tool uses a variety of techniques to gather information and identify potential origin servers:

* **DNS Analysis**: Checks basic `A` records and looks for IPs associated with `MX` (mail) records.
* **Subdomain Scanning**: Scans a list of common subdomains (`dev`, `cpanel`, etc.) that might point directly to the origin server.
* **HTTP Header Inspection**: Analyzes response headers for clues about server software or leaked IPs.
* **Shodan Search (Optional)**: Queries the Shodan database for historical data associated with the domain.
* **WHOIS Enrichment**: Performs a WHOIS lookup on all found IP addresses to identify their owners, helping distinguish between CDNs and hosting providers.

## Installation

To get started, clone the repository and install the required dependencies.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/CypherNova1337/Void_Finder
    cd Void_Finder
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration (Optional)

Void Finder works right out of the box. However, you can enhance its capabilities by adding a Shodan API key.

* Open `void_finder.py` with a text editor.
* Find the `SHODAN_API_KEY` variable and replace the placeholder text with your key.
* **Note**: Effective use of the Shodan search filter generally requires a paid API key. If no key is provided, the script will automatically and safely skip this step.

## Usage

Run the tool from your command line, passing the target domain as an argument.

```bash
python void_finder.py <domain_to_investigate>
```

### Example

```bash
python void_finder.py example.com
```

The script will perform its investigation and print a final report summarizing its findings, separating likely CDN IPs from potential origin server candidates.

## Disclaimer

This tool is intended for educational and professional security assessment purposes only. Always ensure you have permission before scanning any target.
