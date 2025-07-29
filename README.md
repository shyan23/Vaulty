
Vaulty

![alt text](https://img.shields.io/github/stars/your-username/vaulty?style=social)


![alt text](https://img.shields.io/badge/build-passing-brightgreen)


![alt text](https://img.shields.io/badge/license-MIT-blue)


![alt text](https://img.shields.io/badge/version-1.0.0-informational)

Vaulty: Secure, Manage, and Monitor Your Secrets from the Command Line.

Tired of insecure .env files, cumbersome secret management platforms, and a lack of visibility into your API key usage? Vaulty is a developer-first command-line tool designed to solve these problems with a simple, powerful, and secure workflow.

Vaulty transforms your plain-text secrets into encrypted, tamper-proof .vault files. It provides seamless, zero-exposure access to your secrets in your code, complete with rate limiting and a powerful management dashboard.

The Problem

In modern development, managing environment variables and API keys is critical but often insecure:

.env files are plain text, making them a significant security risk if accidentally committed to version control or exposed.

Cloud-based secret managers can be complex to set up and may introduce latency or dependencies you don't need for local development.

Lack of Control: There's no easy way to monitor which keys are being used, how often, or to enforce usage limits directly from your development environment.

The Vaulty Solution

Vaulty provides an end-to-end solution built on strong cryptographic principles and a developer-friendly interface.

(A conceptual diagram representing the workflow)

Create: Define your secrets in a simple text file.

Encrypt: Use the vaulty CLI to generate a secure, encrypted .vault file and a corresponding private key for access.

Access: Use Vaulty's library in your application to fetch secrets on-the-fly without ever exposing them in your code or logs.

Control & Monitor: Launch the Vaulty Dashboard to get a bird's-eye view of all your vaults, track API usage, configure rate limits, and manage secrets.

Key Features

🔐 Asymmetric Encryption Core: Vaulty uses a public/private key pair (SSH-style) to encrypt your vaults. Your private key is your master password—it never leaves your machine and is never stored in the vault itself.

✍️ Simple, Text-Based Input: No complex configuration. Just list your key-value pairs in a text file.

⚡️ One-Command Vault Creation: A single, intuitive command (vaulty make) is all you need to secure your secrets.

💻 Seamless Programmatic Access: A lightweight library allows your applications to request secrets from a vault with a simple get() method. Secrets are never loaded into the environment or printed to the console.

👁️ Intuitive VS Code Integration: When you open a .vault file in VS Code, a custom view shows you the names of the keys stored within, but never their values, for quick reference.

📊 Comprehensive Management Dashboard: A local web-based UI to visualize and control your entire secret ecosystem.

⏱️ Granular Rate Limiting: Protect your APIs from abuse or accidental overuse. Configure global or per-key rate limits (e.g., 100 requests/hour for OPENAI_API_KEY).

⚙️ Centralized Control: The dashboard allows you to add/remove variables, block access to an entire vault, and modify rate limits on the fly.

Getting Started
Installation

Install Vaulty globally using your favorite package manager.

Generated bash
# Using pip (for a Python-based tool)
pip install vaulty-cli

# Or using npm (for a Node.js-based tool)
npm install -g vaulty-cli

Quick Start Workflow

1. Prepare Your Secrets File

Create a file named input.txt (or any name you prefer) with your secrets.

input.txt

Generated ini
# This is my development environment
GEMINI_API_KEY="ai-key-for-gemini-goes-here"
OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Database Credentials
DB_HOST="localhost"
DB_USER="root"
DB_PASS="s3cr3t_p@ssw0rd"
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Ini
IGNORE_WHEN_COPYING_END

2. Create Your First Vault

Run the make command. You can pass one or more input files.

Generated bash
vaulty make input.txt --name dev.vault
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

This command will:

Check if you have a master Vaulty key pair (~/.vaulty/id_rsa & ~/.vaulty/id_rsa.pub). If not, it will generate one for you and save it. Back this up!

Create an encrypted vault file named dev.vault in your current directory.

Print a message confirming the vault was created successfully.

3. Use Secrets in Your Application

Now, you can securely access your variables in your code without exposing them.

app.py

Generated python
import vaulty
import openai

# Load the vault file. The master private key is found automatically.
secrets = vaulty.load('dev.vault')

# Get a key. This returns the value directly to the variable.
# It will NEVER be printed.
openai.api_key = secrets.get('OPENAI_API_KEY')

# If you try to print the secrets object or the key, it will be masked.
print(secrets)  # Output: <VaultyObject for 'dev.vault' with 5 keys>
# print(secrets.get('OPENAI_API_KEY')) -> This action would be blocked by the library.

# Use the API as you normally would
# ... your application logic ...
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Python
IGNORE_WHEN_COPYING_END

4. Launch the Dashboard

To monitor and manage your vaults, run the dashboard command from your project root.

Generated bash
vaulty dashboard
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

This will start a local web server and open a new tab in your browser, pointing to http://127.0.0.1:5050.

The Vaulty Dashboard

The dashboard is your mission control for all secrets in the current project.

(A conceptual mockup of the dashboard)

From here, you can:

View All Vaults: See every .vault file in your project.

Track Usage: Get real-time statistics on:

How many times each vault has been accessed.

How many times each individual API key has been requested via .get().

Manage Rate Limits:

Click on a vault, then on a key, to set or adjust its rate limit (e.g., requests/minute).

Set a global rate limit for all keys within a vault.

Modify Vaults:

Securely add a new key-value pair.

Remove an existing key.

Block/unblock access to an entire vault file with a single toggle.

Security Model

Vaulty is built with a zero-trust, zero-exposure philosophy.

Encryption: Vaults are encrypted using AES-256. The AES key is itself encrypted using your public RSA key.

Decryption: To access a secret, your master private RSA key is required to decrypt the AES key, which then decrypts the data.

Private Key: Your private key (id_rsa) is your identity. It's stored locally on your machine and should be treated like a password. Vaulty will never ask for it or transmit it.

Runtime Safety: The vaulty library is designed to prevent accidental exposure. It intercepts print() or log() calls on secret values and returns a masked string like [VAULTY_SECRET].

Contributing

We welcome contributions! Please read our CONTRIBUTING.md to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes.

License

This project is licensed under the MIT License. See the LICENSE file for details.