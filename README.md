# blackhole 🕳️

This project implements a simple DNS sinkhole with a web-based dashboard for management and monitoring. A DNS sinkhole works by intercepting DNS queries for known malicious domains and returning a safe, non-routable IP address (like `0.0.0.0`) instead of the actual malicious IP. This prevents devices using the sinkhole from connecting to harmful sites.

## Features

*   **DNS Blocking**: Intercepts and blocks DNS queries for domains present in a configurable blocklist.
*   **Configurable Blocklist**: Downloads a blocklist from a specified URL and refreshes it periodically.
*   **Allowlist/Denylist**: Supports custom allowlists and denylists to override blocklist entries.
*   **Web Dashboard**: A simple Flask-based web interface to view statistics, logs, and manage allow/denylists.
*   **Real-time Monitoring**: Displays total queries, blocked queries, and recent DNS activity.

## Setup

Follow these steps to get the DNS Sinkhole running on your system.

### Prerequisites

*   Python 3.x
*   pip (Python package installer)

### Installation

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone https://github.com/your-repo/dns_sinkhole.git
    cd dns_sinkhole
    ```
    *(Assuming a hypothetical repo name for the instruction)*

2.  **Navigate to the project directory:**
    ```bash
    cd dns_sinkhole
    ```
    *(This refers to the inner `dns_sinkhole` directory)*

3.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Configuration

The project uses `config.yaml` for configuration. A sample `config.yaml` is provided. You should review and modify it according to your needs.

1.  **Open `dns_sinkhole/config.yaml` and edit the following:**
    *   `UPSTREAM_DNS`: The IP address of the DNS server to forward non-blocked queries to (e.g., `8.8.8.8` for Google DNS).
    *   `SINKHOLE_IP`: The IP address to return for blocked domains (defaults to `0.0.0.0`).
    *   `BLOCKLIST_URL`: The URL of a plain-text blocklist file. Each line should ideally contain a domain to block, or be in a format like `0.0.0.0 domain.com`. Example: `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`
    *   `BLOCKLIST_REFRESH_INTERVAL`: How often (in seconds) the blocklist should be refreshed.
    *   `WEB_DASHBOARD_PORT`: The port for the web dashboard (e.g., `8080`).
    *   `DNS_PORT`: The port for the DNS server (defaults to `53`). Note: Port 53 usually requires root privileges.
    *   `DNS_HOST`: The IP address the DNS server will listen on (e.g., `0.0.0.0` for all interfaces).

### Running the Application

It is recommended to run the application using the provided `run.sh` script, which handles environment activation and execution.

1.  **Ensure `run.sh` is executable:**
    ```bash
    chmod +x run.sh
    ```

2.  **Run the application:**
    ```bash
    ./run.sh
    ```

    Alternatively, you can run it directly:
    ```bash
    source .venv/bin/activate
    python dns_sinkhole/main.py
    ```

    *(If running on port 53, you might need `sudo` for `run.sh` or `sudo python dns_sinkhole/main.py`)*

## Usage

### Setting up Clients

To use the DNS sinkhole, configure your devices (computers, routers) to use the IP address of the machine running the sinkhole as their primary DNS server.

### Accessing the Web Dashboard

Once the application is running, you can access the web dashboard through your browser:

*   Open `http://<YOUR_SINKHOLE_IP>:<WEB_DASHBOARD_PORT>` (e.g., `http://192.168.1.100:8080`)

The dashboard allows you to:
*   View total and blocked query statistics.
*   See recent DNS query logs.
*   Dynamically update the allowlist and denylist.

## Configuration Details

(More detailed explanation of `config.yaml` parameters will go here, if needed, or link directly to the file.)

## Blocklist Management

The sinkhole fetches its primary blocklist from the `BLOCKLIST_URL` specified in `config.yaml`. It supports `0.0.0.0 domain.com` format and simple `domain.com` per line.

The allowlist and denylist, manageable via the web dashboard API, take precedence over the main blocklist.
