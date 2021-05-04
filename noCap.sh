#!/bin/bash

####################
# noCap by Droogy #
####################

# noCap is a script that processes a PCAP-
# and quickly extracts artifacts and runs a few-
# calculations on basic connection statistics

# make our directory structure
makeDir() {
    printf "[*] Making directory structure\n\r"
    mkdir suricata zeek
    zeek -r *.pcap && mv *.log zeek/
}

# extract files and get sha256 hashes, filetypes and then run AV scans
extractAndScan() {
    printf "[*] Extracting artifacts with tshark and running AV scans\n\r"
    tshark -r *.pcap --export-objects "http,object_exports/" 1>/dev/null
    clamscan -i object_exports/ > clamscan.txt
    yara-rules object_exports/ > yara.txt
    suricata -r *.pcap -l suricata/
}

# hasher stores a space seperated list of sha256 hashes
# paste takes in the input of 'file object_exports/*" and our variable since-
# $hasher stores a space seperated string, sed turns the spaces into newlines-
# so we have a nicely formatted column to paste after the file command, finally-
# awk gets rid of dupe sha256 sums and prints unique lines
typeHasher() {
    hasher=`sha256sum object_exports/* | cut -d ' ' -f 1`
    printf "[*] Getting file-types and SHA256 hashes\n\r"
    paste <(file object_exports/* | cut -d "/" -f 2-) <(echo $hasher | sed 's/ /\n/g') | \
    awk '!seen[$3]++ {print}' > export_files.txt
}

zeekParser() {
    # extract MAC address and associated IP with tshark
    printf "[*] Grabbing IPs and MACs with tshark\n\r"
    tshark -r capture.pcap -T fields -e ip.src -e eth.src | \
    sort | uniq > hostMac.txt
    sed -i "1i HOST\t\tMAC" hostMac.txt

    # start parsing stats from the zeek logs
    clear
    printf "[*] Parsing zeek logs\n\r"
    cat zeek/kerberos.log | zeek-cut id.orig_h client | sort | uniq -i > kerb_clients.txt
    sed -i "1i SRC\t\tCLIENTNAMES" kerb_clients.txt

    # grab DNS originating request host, query, and answer(s) 
    cat zeek/dns.log | zeek-cut id.orig_h query answers | awk '!seen[$2]++ {print}' > \
    dns_hostQueryAnswers.txt
    sed -i "1i SRC\t\tQUERY\t\tANSWER" dns_hostQueryAnswers.txt

    # calculate top 10 longest continuous connection durations
    cat zeek/conn.log | zeek-cut id.orig_h id.resp_h duration | grep -v "-" | \
    sort | datamash -g 1,2 sum 3 | sort -u -k3 -nr | \
    awk '{print $1 "\t" $2 "\t" $3/60" min"}' | head > conn_top10longTalkers.txt
    sed -i "1i SRC\t\tDST\t\tCONN LEN" conn_top10longTalkers.txt

    # calculate top 10 cumulative number of connections between 2 hosts
    cat zeek/conn.log | zeek-cut id.orig_h id.resp_h | sort | \
    datamash -g 1,2 count 2 | sort -k3 -nr | head > conn_top10numConns.txt
    sed -i "1i SRC\t\tDST\t\t#CONNS" conn_top10numConns.txt

    # grabs host and dest IP along with uri requested        
    cat zeek/http.log | zeek-cut id.orig_h id.resp_h host uri > http_sitesVisited.txt
    sed -i "1i SRC\t\tDST\t\tHOST\t\tURI" http_sitesVisited.txt
}

report() {
    clear
    printf "\n\n\n\r
    _____  ______ _____   ____  _____ _______ 
    |  __ \|  ____|  __ \ / __ \|  __ \__   __|
    | |__) | |__  | |__) | |  | | |__) | | |   
    |  _  /|  __| |  ___/| |  | |  _  /  | |   
    | | \ \| |____| |    | |__| | | \ \  | |   
    |_|  \_\______|_|     \____/|_|  \_\ |_|   
    \n\r                                                                                                                                                                                                       
    "
    sleep 2

    # only print private IP and MAC
    # we need a little regex to work with the 172 private IP range
    printf "\n\n***********************************\n\rPRIVATE IP AND MAC\n\r***********************************\n\n\r"
    printf "HOST\t\tMAC\n" && egrep "^(192\.168|10\.|172\.[1-3][0-9]\.)" hostMac.txt

    # look for interesting files we exported and print those out
    printf "\n\n***********************************\n\rEXECUTABLE/INTERESTING FILES\n\r***********************************\n\n\r"
    egrep "(\.exe|\.js|\.dll|\.txt|\.py)$" export_files.txt 2>/dev/null

    # grab kerberos info
    printf "\n\n***********************************\n\rKERBEROS CLIENT IP AND NAMES\n\r***********************************\n\n\r"
    cat kerb_clients.txt

    # first 20 DNS queries
    # we use the pr command to split the DNS query list into 2 columns
    # -w sets the page width to 85 and -T gets rid of the pr headers
    printf "\n\n*********************\n\rFIRST 20 DNS Queries\n\r*********************\n\n\r" \
    && grep -v "QUERY" dns_hostQueryAnswers.txt | awk '{print $2}' | pr -2 -T -w 85 | head -n 15

    # simply print out our top10* logs
    printf "\n\n*********************\n\rTOP 10 LONG CONNECTIONS\n\r*********************\n\n\r"
    cat conn_top10longTalkers.txt

    printf "\n\n***********************************\n\rTOP 10 # OF CUMULATIVE CONNECTIONS\n\r***********************************\n\n\r"
    cat conn_top10numConns.txt
}

main(){
    makeDir
    extractAndScan
    typeHasher
    zeekParser
    report
}

main

