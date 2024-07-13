# DoH Server

An implementation of DNS over HTTPS server, which supports both RFC8484 and dns-json (as same as Cloudflare).
The purpose of this project is mostly for learning and personal use.

## Credits
- [dnsguide](https://github.com/EmilHernvall/dnsguide) for the DNS protocol implementation 


## Specs
### DNS Wireformat 
The format is defined in [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

#### Using POST
```
:method = POST
:scheme = https
:authority = localhost
:path = /dns-query
accept = application/dns-message
content-type = application/dns-message
content-length = 33

<33 bytes represented by the following hex encoding>
00 00 01 00 00 01 00 00  00 00 00 00 03 77 77 77
07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 00 01 00
01
```

**Response**
```
:status = 200
content-type = application/dns-message
content-length = 64
cache-control = max-age=128

<64 bytes represented by the following hex encoding>
00 00 81 80 00 01 00 01  00 00 00 00 03 77 77 77
07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 00 01 00
01 03 77 77 77 07 65 78  61 6d 70 6c 65 03 63 6f
6d 00 00 01 00 01 00 00  00 80 00 04 C0 00 02 01
```

You can change the header `accept = application/dns-json` to request the server return response in JSON format.

#### Using GET
When using GET, the DNS query is encoded into the URL using Base64 with URL-safe and no padding.

```bash
curl -H 'accept: application/dns-message' -v 'https://localhost/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' | hexdump
```

### JSON
The JSON only support query using GET.

**Supported params**
- name (required): the query name
- type (required): the query type (e.g. A, AAAA, NS, MX,...)

**Example**
```bash
curl -H "accept: application/dns-json" "https://localhost/dns-query?name=example.com&type=AAAA"
```

## Quickstart

```bash
# start dependencies with Docker
make run-deps

# start the server
make run

# resolve example.com
curl -H "accept: application/dns-json" "https://localhost/dns-query?name=example.com&type=AAAA"

# benchmark
make bench
```