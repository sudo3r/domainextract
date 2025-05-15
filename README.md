# domainextract
DNS Domain Extraction Tool

## Installation
```shell
pip install requirements.txt
```

## Usage
```
usage: domainextract.py [-h] [-c COUNTRY] [-r RANGE] [-t THREADS] [-o OUTPUT] [-d DNS] [-f] [-b BATCH_SIZE] [-v]

options:
  -h, --help            show this help message and exit
  -c, --country COUNTRY
                        Country code (e.g. US, IR, DE)
  -r, --range RANGE     Custom IP range (e.g., 192.168.1.0/24)
  -t, --threads THREADS
                        Number of threads
  -o, --output OUTPUT   Output file
  -d, --dns DNS         DNS server to use
  -f, --force-update    Force update IP ranges cache
  -b, --batch-size BATCH_SIZE
                        Number of IPs to process at once
  -v, --verbose         Enable verbose output
```
