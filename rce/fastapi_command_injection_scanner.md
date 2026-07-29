# FastAPI Command Injection Scanner

## Overview

The FastAPI Command Injection Scanner is a tool designed to identify command injection vulnerabilities in FastAPI-based applications. Command injection allows attackers to execute arbitrary code on the server by exploiting unsanitized user input. This scanner leverages fingerprints to detect FastAPI applications and actively probes for vulnerabilities using controlled payloads.

## Features

- Fingerprinting and identification of FastAPI services
- Active probing for command injection vulnerabilities
- Toggle safe mode for detection-only scanning
- Concurrency limits for efficient bulk scanning
- JSON output for result archival and analysis
- CLI options for detailed customization

## Usage

### Scan a single target
