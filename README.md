# vscan-crlf-injection-detector
Identifies potential CRLF injection vulnerabilities by injecting CRLF sequences in headers and parameters and monitoring server responses. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-crlf-injection-detector`

## Usage
`./vscan-crlf-injection-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: URL parameters to test (e.g., 
- `-H`: Custom headers to include (e.g., 
- `-crlf`: Custom CRLF payload
- `-t`: Request timeout in seconds
- `--user-agent`: Custom User-Agent header

## License
Copyright (c) ShadowGuardAI
