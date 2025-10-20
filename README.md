# CURL to Repeater - Burp Suite Extension

A Burp Suite extension that converts cURL commands from clipboard directly to Burp Repeater with advanced GraphQL support.

## What it does

- **Right-click Integration**: Adds "Paste cURL command to Repeater" to context menus
- **Smart Parsing**: Handles complex cURL commands with various quoting styles and escape sequences  
- **GraphQL Detection**: Automatically detects and formats GraphQL requests for better readability
- **Complete Support**: Works with all cURL options (-H, -d, --data, -X, -b, etc.)
- **Bash Compatibility**: Processes bash $'...' quoting with Unicode, hex, and octal escapes

## Installation

1. Download Curl2Repeater.py
2. In Burp Suite: Extensions → Add → Python → Select file
3. Extension loads automatically

## Usage

1. Copy any cURL command to clipboard
2. Right-click anywhere in Burp Suite
3. Select "Paste cURL command to Repeater" 
4. Request appears in new Repeater tab

## Features
✅ All cURL data formats (JSON, form-encoded, raw, binary)

✅ GraphQL detection and formatting

✅ Advanced escape sequence processing

✅ Automatic HTTP method promotion (GET → POST when data present)

✅ Header and cookie extraction

✅ Error handling with user feedback


#### Note: 
I created this extension for my use case - it might have bugs but feel free to raise issues if you encounter any problems. 

Original Idea - https://github.com/portswigger/paste-curl-to-repeater


