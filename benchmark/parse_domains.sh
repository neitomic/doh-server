#!/bin/bash

# parsing the domains in csv from cloudflare to quoted domain list for
# pasting into lua wrk script.
# Expected list of quoted domains with comma at the end
# ```
# "google.com",
# "googleapis.com",
# "root-servers.net",
# ```



# Check if input file is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <input_csv_file>"
    exit 1
fi

input_file=$1

# Process the CSV file and output to command line
awk -F',' 'NR>1 {print "\""$2"\","}' "$input_file"