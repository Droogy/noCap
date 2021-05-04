# Project Title

noCap 

## Description

noCap is a PCAP parsing script which does the following:
    1. Creates directory structure
    2. Extract artifacts (if there are any), hash them and run a YARA and ClamAV scan against them
    3. Enumerate private IP hosts and list IP and MAC
    4. Run Suricata against the PCAP
    5. Run Zeek against the PCAP
    6. Parses the Zeek logs and runs a couple basic calculations to find possible pivot points for further investigation

## Getting Started

### Dependencies

You will need the following tools installed:
 1. `datamash`
 2. `pr`
 3. `suricata`
 4. `yara`
 5. `clamscan`
 6. `tshark`
 7. `zeek`
 8. `egrep`

### Installing

* Clone this repository or just copy and paste the script
* Please note you may not have the `yara-rules` alias

### Executing program

* Create a clean directory to work out of, this script will create a lot of files
* Move the script and your PCAP file into the **same** folder
* Mark script as executable with `chmod +x ./noCap` 
* Then just execute, noCap doesn't take any arguments

```
./noCap
```

## Help

Double-check you have all the correct tools installed.
The Remnux alias `yara-rules` is referenced in the script, you may need to alter this part in the script or add the alias instead.

## Authors

Droogy
[@xDroogy](https://twitter.com/xDroogy)


## Acknowledgments

* [RITA](https://github.com/activecm/rita)
* [Installing YARA](https://yara.readthedocs.io/en/stable/gettingstarted.html)
* [Suricata](https://suricata.readthedocs.io/en/suricata-6.0.0/install.html)
* [Awesome PCAP Tools](https://github.com/caesar0301/awesome-pcaptools)