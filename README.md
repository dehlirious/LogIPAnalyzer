# Advanced Log Analyzer

Advanced Log Analyzer is a versatile PHP tool for parsing, analyzing, and managing server log files. It excels in extracting detailed information from logs and integrates seamlessly with various IP blocklists to enhance security.

## What is it?
- Advanced Log Analyzer is specifically engineered for processing 'access' logs from nginx servers. It uses a regex-based parsing mechanism within the `__construct` method to dissect log entries. The tool compares IPs against 32 renowned BadIP lists (as detailed in `blockLists`) and filters out suspicious ones. These IPs are then formatted into `deny $IP;\n` syntax, ready to be incorporated into your nginx.conf file for blocking unwanted traffic.
## Why, exactly?
- This tool offers a more targeted approach to blocking IPs. Instead of indiscriminately blocking a massive list of IPs(10mb+ within the lists of this script), it focuses on those actively crawling and targeting your website.
- It's built to handle large datasets and log files somewhat efficiently, making it scalable for high-volume web environments. (Note: This is still in beta and has not been tested with anything over 10mb worth of access logs)

   
## Features

- **Robust Log Parsing**: Parses nginx server logs with a sophisticated regex pattern, customizable for different log formats.
- **IP Blocklist Integration**: Integrates with 32 different IP blocklists for comprehensive security coverage.
- **Efficient IP Filtering**: Filters and saves suspicious IPs in a format ready for nginx.conf, reducing unnecessary IP blocking.
- **Data Aggregation and Analysis**: Offers extensive capabilities for data aggregation, counting, and insightful analysis.
- **Advanced Search Capabilities**: Facilitates deep search functionality based on various log fields, values, and time ranges.
- **Dual IP Support**: Equipped to handle both IPv4 and IPv6 addresses, including those in CIDR notation.
- **Intelligent Whitelisting**: Incorporates whitelisting features, including compatibility with Cloudflare IP ranges.
- **Performance-Centric Design**: Optimized for processing large log files without compromising on performance.


## Use Cases

- **Proactive Security Measures**: Enables proactive security by detecting and blocking malicious IPs targeting your website.
- **Insightful User Behavior Analysis**: Gain insights into user behavior and patterns through detailed log analysis.
- **Efficient Performance Monitoring**: Monitor and enhance server performance by analyzing critical metrics from log files.
- **Enhanced Network Security**: Bolster your network security posture by managing and utilizing IP blocklists effectively.


## Getting Started

### Prerequisites

- PHP 7.4 or higher.
- Access to server log files in the specified format.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dehlirious/LogIPAnalyzer.git
2. Modify `$pattern` to match your nginx access logs format
3. Modify `$cacheDirectory`
4. Depending on use-case, modify the `writeIpsToFile` function.

### PHP Demonstrations
- Initialize the Log Analyzer
   ```php
   $log = new LogAnalyzer('nginxlog.log');
- Save Suspicious IPs to File
  ```php
  $var = $log->checkSuspiciousLogs('clientIP,requestDetails', true);
  $log->writeIpsToFile($var, '/var/www/secret/bans.log');

- Count Parsed Log Lines
  ```php
  $numberOfLines = count($log->logData);
  echo "Total number of logged lines: $numberOfLines";
  
- Search Logs by Specific Field and Value
  
  ```php
  $searchResults = $log->searchLogs('clientIP', '1.1.1.1');
  
- Frequency Analysis of Specific Fields
  
  ```php
  
  $frequency = $log->calculateFieldFrequencyByDay('clientIP');
  
- Additional complex queries and analysis can be performed as well.


## Acknowledgments

A heartfelt thank you to all the authors, websites, and services who maintain the IP blocklists utilized in the Advanced Log Analyzer. Your tireless efforts in identifying, tracking, and sharing information about potentially malicious IP addresses play a crucial role in enhancing online security.

Special mentions go out to:
- The teams behind Known Scanners, Brute Force Login, and Strong IPs blocklists for their comprehensive lists of suspicious IPs.
- The creators of the CINS Score, Feodo Tracker, and DROP Attackers blocklists for helping identify high-risk IP addresses.
- The contributors to the Mirai Security Gives, Emerging Threats Compromised IPs, and Rescue Me blocklists for their focus on specific threats and vulnerabilities.
- The maintainers of the CVE-2021-44228 IPs, Feodo Tracker Recommended, and Scriptzteam IP blocklists for their valuable insights into evolving cyber threats.
- The GreenSnow, NebLink Clean IP, and Stamparm Ipsum teams for their extensive research and data compilation efforts.
- The individuals and groups behind the Bad Packets, Matthew Roberts Threatlist, and AlienVault Reputation blocklists for their detailed and frequently updated lists.
- The ABUSEIPDB, ROFA, LittleJake, RJM, Blocklist.de, and SSL IP Blacklist compilers for their diverse and specialized blocklists.

Your contributions not only empower this tool but also significantly contribute to the safety and security of countless online platforms and users. We are deeply grateful for your dedication and commitment to cybersecurity.

