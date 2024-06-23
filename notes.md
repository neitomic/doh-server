# Notes

## DNS in a nutshell

Main record types
1. A
2. AAAA
3. CNAME
4. NS
5. MX

A for address
- points to IPv4 for a specific hostname or domain

AAAA
- similar to A but points to IPv6

CNAME (canonical name)
- points to a domain name (alias for other domain)
- `ftp.example.com` for file transfer protocol (FTP) and serve webpages via `www.example.com`.
  Use CNAME to point both to `example.com`

NS (nameserver)
- points to which server to loop up IP for a domain

MX (mail exchange)
- points to mail server emails for a domain should be routed to
