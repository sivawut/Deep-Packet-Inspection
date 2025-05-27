# Deep-Packet-Inspection

Obfuscated Link Detection using Deep Packet Inspection (DPI)

Overview

This project implements a Deep Packet Inspection (DPI) tool installed on Debian Linux. It acts as a Man-in-the-Middle (MITM) to inspect both incoming (ingress) and outgoing (egress) traffic in real time. The system extracts and analyzes URLs to detect obfuscated or malicious links and presents the results through a real-time dashboard.

Features

Real-time MITM packet capture and HTTPS interception

URL extraction from HTTP requests, DNS responses, and TLS sessions

Detection of obfuscated URLs using regex, entropy, and threat intelligence

Redirection chain unwrapping

Threat scoring engine with classification (obfuscated, suspicious, malicious)

Web-based dashboard showing detections and statistics

Runs on Debian Linux using iptables, mitmproxy, and Python

Architecture



Components

1. Packet Capture

Tools: tcpdump, iptables, mitmproxy

Extract raw network traffic at Layer 7

2. DPI Parser

Language: Python (using scapy, dpkt, or pyshark)

Extract URLs from HTTP headers, body, and DNS answers

3. Detection Engine

URL entropy analysis

Regex for URL encoding (hex, base64, unicode)

Integration with threat intelligence APIs (e.g., VirusTotal)

4. Dashboard

Framework: Flask, Chart.js, Bootstrap

Features:

Obfuscated URL list

Source IP, timestamp, and destination domain

URL redirection path visualization

5. Storage

Local database (SQLite or MongoDB) for detected URLs and metadata
