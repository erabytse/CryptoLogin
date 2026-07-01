# CryptoLogin CLI Examples

Simple examples demonstrating CryptoLogin usage from the command line.

## Prerequisites

```bash
pip install cryptologin

```

## Basic Usage

```bash
# Initialize CryptoLogin
cryptologin init

# Start the server
cryptologin run --port 8000

# Register a user
cryptologin register --secret "my-master-secret-min-32-chars"

# Login
cryptologin login --secret "my-master-secret-min-32-chars"

# List users
cryptologin users

# Show status
cryptologin status
```

## Python Script Usage

**See** basic_usage.py **and** advanced_usage.py **for programmatic examples**.

## Running the Examples

```bash
# Basic example
python basic_usage.py

# Advanced example
python advanced_usage.py
```
