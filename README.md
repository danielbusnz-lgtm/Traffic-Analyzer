# Traffic Analyzer

Network traffic analyzer and packet capture tool written in Rust.

## Features

- Real-time packet capture and analysis
- Network interface selection
- Support for multiple protocols (TCP, UDP, IPv4)
- Command-line interface

## Requirements

- Rust 1.70 or higher
- libpcap development libraries

### Platform-specific dependencies

#### Linux
```bash
sudo apt-get install libpcap-dev
```

#### macOS
```bash
brew install libpcap
```

## Installation

```bash
git clone https://github.com/danielbusnz-lgtm/Traffic-Analyzer.git
cd Traffic-Analyzer
cargo build --release
```

## Usage

```bash
# Run with automatic interface selection
cargo run

# Specify network interface
cargo run -- eth0

# Read from pcap file
cargo run -- --file capture.pcap
```

### Permissions

On Linux and macOS, packet capture requires elevated privileges:

```bash
sudo cargo run
```

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

## License

This project is licensed under the MIT License.
