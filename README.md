# SPKI Trust Evaluator (Swift)

Swift test client demonstrating SPKI pinning validation using Alamofire.

## Overview

This project provides a minimal iOS SwiftUI application that validates a server connection using SPKI pinning.  
It is intended for testing and understanding certificate public key pinning behavior.

## Features

- SPKI hash comparison
- Alamofire-based networking
- Custom ServerTrustEvaluator
- Console-based validation output
- Single-host test configuration

## Usage

1. Set the target host
2. Replace the placeholder SPKI hash
3. Run the app in Simulator
4. Observe validation output in Xcode console

## Example placeholders

example.your-domain.com
REPLACE_WITH_BASE64_SPKI_HASH

## Purpose

This repository is intended as a minimal reference implementation for SPKI pinning validation in Swift using Alamofire.
