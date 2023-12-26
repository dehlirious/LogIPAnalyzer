<?php
/*
 * Known Issues & To-Do list:
 * Make the format of whats saved to bans.log variable. 
 * debugging step @ regex, show how many matches were made, so you can tell if any are being made, Big headache if none are being made
 * Support more Ban IP Lists types; Currently it's limited in scope!
 * Support Whitelisted Ipv6 IPs & ranges if not already (I made this long ago, can't remember)
 *
 * Regular Expression for Log Parsing: Consider edge cases where log format might slightly differ.
 * Blocklists URLs: Consider loading them from a configuration file or database for easier updates
 * Error Handling: Consider more robust error handling, especially for network requests (cURL) and file operations.
 * Performance Considerations: Depending on log file size, loading the entire file into memory might not be efficient. Consider processing the file line by line.
 * The method fetchAndCacheLists() could be optimized for better performance, especially if dealing with large blocklists.
 * Code Duplication: There are repeated patterns in the code (e.g., in isIpWhitelisted). 
 * Unit Testing: Consider adding unit tests for ensure reliability and maintainability.
 * 
 * 
 * 
*/

//set_time_limit(32000);
class LogAnalyzer {
	public $logData = [];
	public $counters = [];
	private $cacheDirectory = 'baniplists';
	private $cacheExpiry = 86400; // 24 hours in seconds
	
	// Example - This log format would work with the existing regex!
	//log_format cloudflare '[$time_local] _{^&*}_ $host _{^&*}_ $http_cf_connecting_ip _{^&*}_ $remote_addr _{^&*}_ '
	//   '$request _{^&*}_ $status _{^&*}_ $body_bytes_sent _{^&*}_ $http_user_agent _{^&*}_ $http_referer _{^&*}_ '
	//   '$request_time _{^&*}_ $upstream_response_time _{^&*}_ $request_length _{^&*}_ $connection _{^&*}_ $sent_http_content_type ;;;';
	
	// Define a regular expression pattern to match log entries and extract data.
	// MUST MODIFY ACCORDING TO YOUR OWN NGINX LOG FORMAT !!
	private $pattern = '/^\[([^\]]+)\] _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) /';
	
	// Create an array that maps the placeholders to meaningful names.
	// This be used for processing log entries
	public $logKeys = [
		"time", 		  // $time_local
		"host", 		  // $host
		"connectingIP",   // $http_cf_connecting_ip
		"clientIP", 	  // $remote_addr
		"requestDetails", // $request
		"responseCode",   // $status
		"bodyBytesSent",  // $body_bytes_sent
		"browserInfo",	  // $http_user_agent
		"sourceURL", 	  // $http_referer
		"requestTime", 	  // $request_time
		"upstreamResponseTime", // $upstream_response_time
		"requestLength",  // $request_length
		"connection", 	  // $connection
		"contentType"	  // $sent_http_content_type
	];
	
	private $blockLists = [
		// Known Scanners Blocklist - Contains known scanner IP addresses.
		'https://www.neblink.net/blocklist/KnownScanners.txt',

		// Brute Force Login Blocklist - Contains IP addresses associated with brute force login attempts.
		'https://lists.blocklist.de/lists/bruteforcelogin.txt',

		// Strong IPs Blocklist - Contains a list of strong (possibly malicious) IP addresses.
		'https://lists.blocklist.de/lists/strongips.txt',

		// CINS Score Blocklist - Contains IP addresses with a high CINS score indicating suspicious activity.
		'https://cinsscore.com/list/ci-badguys.txt',

		// Feodo Tracker Blocklist - Includes IP addresses associated with the Feodo (Dridex) botnet.
		'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',

		// DROP Attackers Blocklist - Contains IP addresses associated with malicious activity.
		'https://report.cs.rutgers.edu/DROP/attackers',

		// Mirai Security Gives Blocklist - Includes IP addresses associated with Mirai botnet.
		'https://mirai.security.gives/data/ip_list.txt',

		// Emerging Threats Compromised IPs Blocklist - Contains IP addresses associated with compromised systems.
		'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',

		// Rescure Me Blocklist - Contains IP addresses associated with malicious activity.
		'https://rescure.me/rescure_blacklist.txt',

		// CVE-2021-44228 IPs Blocklist - Includes IP addresses related to CVE-2021-44228 vulnerability.
		'https://gist.githubusercontent.com/gnremy/c546c7911d5f876f263309d7161a7217/raw/eac647ffb2e2cc1193be7e8b2f9cf96080278a04/CVE-2021-44228_IPs.csv',

		// Feodo Tracker Recommended Blocklist - Recommended IP addresses associated with Feodo (Dridex) botnet.
		'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',

		// Scriptzteam IP Blocklist - Contains IP addresses associated with various threats.
		'https://raw.githubusercontent.com/scriptzteam/IP-BlockList-v4/master/ips.txt',

		// GreenSnow Blocklist - Contains IP addresses known for malicious activity.
		'https://blocklist.greensnow.co/greensnow.txt',

		// NebLink Clean IP Blocklist - Contains clean (non-malicious) IP addresses.
		'https://www.neblink.net/blocklist/IP-Blocklist-clean.txt',

		// Stamparm Ipsum Blocklist - Contains IP addresses known for malicious activity.
		'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',

		// Bad Packets Blocklist - Contains IP addresses associated with bad packets or malicious activity.
		'https://raw.githubusercontent.com/tg12/bad_packets_blocklist/master/bad_packets_list.txt',

		// Matthew Roberts Threatlist - Includes IP addresses associated with threats.
		'https://www.matthewroberts.io/api/threatlist/latest',

		// AlienVault Reputation Blocklist - Contains IP addresses with questionable reputation.
		'https://reputation.alienvault.com/reputation.generic',

		// Bad RDP IP Blocklist (ABUSEIPDB 1) - Includes IP addresses associated with RDP abuse.
		'https://raw.githubusercontent.com/m-holler/BAD-RDP-IP/master/ABUSEIPDB_1.txt',

		// Bad RDP IP Blocklist (ABUSEIPDB 2) - Includes additional IP addresses associated with RDP abuse.
		'https://raw.githubusercontent.com/m-holler/BAD-RDP-IP/master/ABUSEIPDB_2.txt',

		// Bad RDP IP Blocklist (ABUSEIPDB) - Includes more IP addresses associated with RDP abuse.
		'https://raw.githubusercontent.com/m-holler/BAD-RDP-IP/master/ABUSEIPDB.txt',

		// ROFA Block IP Blocklist - Contains IP addresses associated with abuse.
		'https://raw.githubusercontent.com/m-holler/BAD-RDP-IP/master/ROFA_BLOCK_IP.txt',

		// LittleJake All Blacklist - Comprehensive list of malicious IP addresses.
		'https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/all_blacklist.txt',

		// LittleJake AbuseIPDB Blacklist (Score 75+) - Includes IP addresses with a high AbuseIPDB score.
		'https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/abuseipdb_blacklist_ip_score_75.txt',

		// LittleJake AbuseIPDB Blacklist (Score 100+) - Includes IP addresses with an even higher AbuseIPDB score.
		'https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/abuseipdb_blacklist_ip_score_100.txt',

		// USTC Blacklist IP Blocklist - Contains IP addresses associated with threats and malicious activity.
		'https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/ustc_blacklist_ip.txt',

		// RJM Sizzling Fresh IPs Blocklist - Includes fresh IP addresses associated with malicious activity.
		'https://rjmblocklist.com/sizzling/freships.txt',

		// RJM Sizzling Worst IPs Blocklist - Contains worst IP addresses known for malicious activity.
		'https://rjmblocklist.com/sizzling/worst.txt',

		// RJM Free Bad IPs Blocklist - Contains free IP addresses associated with bad activity.
		'https://rjmblocklist.com/free/badips.txt',

		// Blocklist.de All Blocklist - Comprehensive list of blocklisted IP addresses.
		'https://lists.blocklist.de/lists/all.txt',

		// Blocklist.de Bots Blocklist - Contains IP addresses associated with bots and malicious activity.
		'https://lists.blocklist.de/lists/bots.txt',

		// SSL IP Blacklist - Includes IP addresses known for SSL-related abuse.
		'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',

		// Additional blocklist URLs can be added as needed.
	];
	
	/**
	 * Constructor for initializing log file parsing.
	 *
	 * @param string $logFilePath - The path to the log file to be parsed.
	 *
	 * @throws InvalidArgumentException - If the specified log file is not readable.
	 */
	public function __construct($logFilePath) {
		if (!is_readable($logFilePath)) {
			throw new InvalidArgumentException("Cannot read file: $logFilePath");
		}

		$logFile = new SplFileObject($logFilePath);

		foreach ($this->logKeys as $key) {
			$this->counters[$key] = [];
		}

		// Loop through the log file, parse log entries, and aggregate counts.
		while (!$logFile->eof()) {
			$logLine = $logFile->fgets();
			$matches = [];
			if (preg_match($this->pattern, $logLine, $matches)) {
				array_shift($matches);
				$parsedData = array_combine($this->logKeys, $matches);
				$this->logData[] = $parsedData;
				$this->aggregateCounts($parsedData);
			}
		}
	}

	/**
	 * Aggregate counts of log data based on specified log keys.
	 *
	 * @param array $log - An associative array representing parsed log data.
	 * @return void
	 */
	private function aggregateCounts($log) {
		// Walk through log keys and update counters.
		array_walk($this->logKeys, function ($key) use ($log) {
			if (isset($log[$key])) {
				$this->counters[$key][$log[$key]] = ($this->counters[$key][$log[$key]] ?? 0) + 1;
			}
		});
	}

	/**
	 * Analyze log data and sort counters in descending order.
	 *
	 * @return array - An array containing sorted counters for log data.
	 */
	public function analyzeLogs() {
		// Sort each counter in descending order.
		foreach ($this->counters as & $counter) {
			arsort($counter);
		}
		return $this->counters;
	}

	/**
	 * Search log data for entries matching a specific field and value.
	 *
	 * @param string $searchField - The log field to search within.
	 * @param mixed $searchValue - The value to search for within the specified field.
	 * @return array - An array containing log entries that match the search criteria.
	 */
	public function searchLogs($searchField, $searchValue) {
		$results = [];
		// Loop through parsed log data and check for matches.
		foreach ($this->logData as $parsedLine) {
			if (isset($parsedLine[$searchField]) && $parsedLine[$searchField] === $searchValue) {
				$results[] = $parsedLine;
			}
		}

		return $results;
	}

	/**
	 * Search log data for entries that match a specified key-value pair.
	 *
	 * @param string $key - The log field to search within.
	 * @param mixed $value - The value to search for within the specified field.
	 * @return array - An array containing log entries that match the key-value pair.
	 */
	public function searchLogsByKeyValue($key, $value) {
		return array_filter($this->logData, function ($log) use ($key, $value) {
			return isset($log[$key]) && $log[$key] === $value;
		});
	}

	/**
	 * Search log data for entries that match a specified time range and key-value pair.
	 *
	 * @param DateTime $start - The start date and time of the time range.
	 * @param DateTime $end - The end date and time of the time range.
	 * @param string $key - The log field to search within.
	 * @param mixed $value - The value to search for within the specified field.
	 * @return array - An array containing log entries that match the time range and key-value pair.
	 */
	public function searchLogsByTimeAndKeyValue(DateTime $start, DateTime $end, $key, $value) {
		return array_filter($this->logData, function ($log) use ($start, $end, $key, $value) {
			if (isset($log['time']) && isset($log[$key])) {
				$logTime = DateTime::createFromFormat('d/M/Y:H:i:s O', $log['time']);
				return $logTime && $logTime >= $start && $logTime <= $end && $log[$key] === $value;
			}
			return false;
		});
	}

	/**
	 * Count the number of log entries that match a specified key-value pair.
	 *
	 * @param string $key - The log field to count entries for.
	 * @param mixed $value - The value to count entries for within the specified field.
	 * @return int - The count of log entries that match the key-value pair.
	 */
	public function countVisitsByKeyValue($key, $value) {
		$count = 0;
		foreach ($this->logData as $log) {
			if (isset($log[$key]) && $log[$key] === $value) {
				$count++;
			}
		}
		return $count;
	}

	/**
	 * Get the frequency of values in a specified log field.
	 *
	 * @param string $field - The log field to calculate frequency for.
	 * @return array - An associative array containing values from the field as keys and their frequencies as values.
	 */
	public function getFrequencyOfField($field) {
		$frequency = [];
		foreach ($this->logData as $log) {
			if (isset($log[$field])) {
				if (!isset($frequency[$log[$field]])) {
					$frequency[$log[$field]] = 1;
				}
				else {
					$frequency[$log[$field]]++;
				}
			}
		}
		return $frequency;
	}

	/**
	 * Get a list of visited pages that match a specified key-value pair.
	 *
	 * @param string $key - The log field to search within.
	 * @param mixed $value - The value to search for within the specified field.
	 * @return array - An array containing unique visited page URLs that match the key-value pair.
	 */
	public function visitedPagesByKeyValue($key, $value) {
		$visitedPages = [];
		foreach ($this->logData as $log) {
			if (isset($log[$key]) && $log[$key] === $value && isset($log['requestDetails'])) {
				$requestDetails = explode(' ', $log['requestDetails']);
				if (isset($requestDetails[1])) {
					$page = $requestDetails[1];
					if (!in_array($page, $visitedPages)) {
						$visitedPages[] = $page;
					}
				}
			}
		}
		return $visitedPages;
	}

	/**
	 * Search log data for entries within a specified time period.
	 *
	 * @param DateTime $start - The start date and time of the time period.
	 * @param DateTime $end - The end date and time of the time period.
	 * @return array - An array containing log entries that fall within the specified time period.
	 */
	public function searchLogsByTimePeriod(DateTime $start, DateTime $end) {
		$results = [];
		foreach ($this->logData as $log) {
			$logTime = new DateTime($log['time']);
			if ($logTime >= $start && $logTime <= $end) {
				$results[] = $log;
			}
		}
		return $results;
	}

	/**
	 * Search log data for entries that match a specified field-value pair and fall within a specified time period.
	 *
	 * @param string $field - The log field to search within.
	 * @param mixed $value - The value to search for within the specified field.
	 * @param DateTime $start - The start date and time of the time period.
	 * @param DateTime $end - The end date and time of the time period.
	 * @return array - An array containing log entries that match the field-value pair and fall within the specified time period.
	 */
	public function searchLogsByFieldAndTimePeriod($field, $value, DateTime $start, DateTime $end) {
		$results = [];
		foreach ($this->logData as $log) {
			$logTime = new DateTime($log['time']);
			if (isset($log[$field]) && $log[$field] === $value && $logTime >= $start && $logTime <= $end) {
				$results[] = $log;
			}
		}
		return $results;
	}

	/**
	 * Process log data and calculate the frequency of a specified field's values for each day.
	 *
	 * @param string $fieldName - The log field to calculate the frequency for.
	 * @return array - An associative array where keys are dates (Y-m-d) and values are arrays of field values with their frequencies.
	 */
	public function calculateFieldFrequencyByDay($fieldName) {
		$frequencyByDay = [];

		foreach ($this->logData as $parsedLine) {
			if (isset($parsedLine['time']) && isset($parsedLine[$fieldName])) {
				$logTime = DateTime::createFromFormat('d/M/Y:H:i:s O', $parsedLine['time']);
				$day = $logTime ? $logTime->format('Y-m-d') : null;

				$fieldValue = $parsedLine[$fieldName];

				if ($day) {
					if (!isset($frequencyByDay[$day][$fieldValue])) {
						$frequencyByDay[$day][$fieldValue] = 0;
					}
					$frequencyByDay[$day][$fieldValue]++;
				}
			}
		}

		// Sort the frequency by day
		ksort($frequencyByDay);

		return $frequencyByDay;
	}

	/**
	 * Fetch and cache block lists for suspicious IPs.
	 * If cached lists are older than the cache expiry time, they are re-downloaded.
	 *
	 * @throws Exception - If there's an issue creating the cache directory.
	 */
	private function fetchAndCacheLists() {
		if (!file_exists($this->cacheDirectory)) {
			mkdir($this->cacheDirectory, 0777, true);
		}

		// Loop through block lists and update cache if needed.
		foreach ($this->blockLists as $listName => $url) {
			$cacheFilePath = "$this->cacheDirectory/$listName.txt";

			if (file_exists($cacheFilePath) && time() - filemtime($cacheFilePath) < $this->cacheExpiry) {
				continue;
			}

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_TIMEOUT, 15);

			curl_setopt($ch, CURLOPT_URL, $url);
			$output = curl_exec($ch);

			$statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			if ($statusCode === 200) {
				$ips = $this->extractIps($output);
				file_put_contents($cacheFilePath, implode("\n", $ips));
			}

			curl_close($ch);
		}
	}

	/**
	 * Check suspicious log entries based on provided IP addresses.
	 *
	 * @param string $fields - Comma-separated field names to include in the result.
	 * @param bool $includeSource - Whether to include the IP source in the result.
	 * @return array - An array of suspicious log entries.
	 */
	public function checkSuspiciousLogs($fields = '', $includeSource = false) {
		$suspiciousIps = $this->getSuspiciousIps();

		$fieldsx = explode(',', $fields);

		$suspiciousLogs = [];
		// Loop through log entries and filter suspicious ones.
		foreach ($this->logData as $log) {
			if (isset($log['clientIP']) && $this->isIpSuspicious($log['clientIP'], $suspiciousIps)) {
				$filteredLog = [];
				// Include specified fields in the filtered log.
				if (!empty($fieldsx)) {
					foreach ($fieldsx as $field) {
						if (isset($log[$field])) {
							$filteredLog[$field] = $log[$field];
						}
					}
				}
				else {
					$filteredLog = $log;
				}

				// Include the IP source if $includeSource is true
				if ($includeSource) {
					$filteredLog['blsource'] = $suspiciousIps[$log['clientIP']];
				}

				$suspiciousLogs[] = $filteredLog;
			}
		}

		return $suspiciousLogs;
	}

	/**
	 * Get suspicious IP addresses by fetching and processing block lists.
	 *
	 * @return array - An array of suspicious IP addresses with their sources.
	 */
	private function getSuspiciousIps() {
		$this->fetchAndCacheLists();

		$suspiciousIps = [];

		// Loop through block lists to read cached IPs and sources.
		foreach ($this->blockLists as $listName => $url) {
			$cacheFilePath = "$this->cacheDirectory/$listName.txt";
			if (file_exists($cacheFilePath)) {
				$ips = file($cacheFilePath, FILE_IGNORE_NEW_LINES);
				foreach ($ips as $ip) {
					if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
						if (strpos($ip, '/') !== false) {
							// IP range detected, expand it into individual IPs
							$expandedIps = $this->expandIpv4Range($ip);
							foreach ($expandedIps as $expandedIp) {
								$suspiciousIps[$expandedIp] = $url;
							}
						}
						else {
							// Store IP source and IP address as key-value pairs
							$suspiciousIps[$ip] = $url;
						}
					}
				}
			}
		}

		//array_unique did weird+cool stuff
		return $suspiciousIps;
	}

	/**
	 * Check if an IP address is suspicious based on a list of suspicious IPs.
	 *
	 * @param string $ip - The IP address to check.
	 * @param array $suspiciousIps - An array of suspicious IP addresses.
	 * @return bool - True if the IP is suspicious, false otherwise.
	 */
	private function isIpSuspicious($ip, $suspiciousIps) {
		return isset($suspiciousIps[$ip]);
	}

	/**
	 * Extract IP addresses from a given data source. Supports URL retrieval, CSV parsing, and CIDR expansion.
	 *
	 * @param string $data - The data source containing IP addresses.
	 * @return array - An array of extracted IP addresses.
	 */
	private function extractIps($data) {
		$ips = [];
		$lines = preg_split('/\R/', $data); // Split the data by new lines (handles different line endings)
		foreach ($lines as $line) {
			$line = trim(explode("#", $line, 2) [0]); // Remove comments and trim the line
			if ($line === '') {
				continue; // Skip empty lines
				
			}

			if (filter_var($line, FILTER_VALIDATE_URL)) {
				$urlContents = file_get_contents($line);
				$urlIps = $this->extractIps($urlContents);
				$ips = array_merge($ips, $urlIps);
			}
			elseif (strpos($line, ',') !== false || strpos($line, "\t") !== false) {
				$values = str_getcsv($line, ',', '"'); // Parse the line as CSV
				$ip = trim($values[0]);

				if ($this->isIpWhitelisted($ip)) {
					continue; // Skip if IP is whitelisted
					
				}

				$ips[] = $ip;
			}
			else {
				if ($this->isIpWhitelisted($line)) {
					continue; // Skip if IP is whitelisted
					
				}

				if (strpos($line, '/') !== false) {
					$ipRange = $this->expandCIDR($line);
					$ips = array_merge($ips, $ipRange);
				}
				else {
					$ips[] = $line;
				}
			}
		}

		return $ips;
	}

	/**
	 * Expand an IPv4 range represented as a string (e.g., "startIp-endIp") into an array of individual IP addresses.
	 *
	 * @param string $range - The IPv4 range string.
	 * @return array - An array of individual IP addresses within the range.
	 */
	private function expandIpv4Range($range) {
		list($start, $end) = explode('-', $range);
		$startIp = ip2long(trim($start));
		$endIp = ip2long(trim($end));

		$ips = [];
		for ($ip = $startIp;$ip <= $endIp;$ip++) {
			$ips[] = long2ip($ip);
		}

		return $ips;
	}
	
	/**
	 * Check if an IPv6 address is within a specified network and mask range.
	 *
	 * @param string $ip - The IPv6 address to check.
	 * @param string $network - The IPv6 network address.
	 * @param int $mask - The subnet mask length.
	 * @return bool - True if the IPv6 address is within the specified range, false otherwise.
	 */
	function ip6_in_range($ip, $network, $mask) {
		$ip_dec = gmp_init(bin2hex(inet_pton($ip)) , 16);
		$network_dec = gmp_init(bin2hex(inet_pton($network)) , 16);

		$mask_dec = gmp_sub(gmp_pow(2, 128) , 1);
		$mask_dec = gmp_xor($mask_dec, gmp_sub(gmp_pow(2, 128 - $mask) , 1));

		$network_start = gmp_and($network_dec, $mask_dec);
		$network_end = gmp_or($network_start, gmp_not($mask_dec));

		return gmp_cmp($ip_dec, $network_start) >= 0 && gmp_cmp($ip_dec, $network_end) <= 0;
	}

	/**
	 * Expand a CIDR notation IP range into an array of individual IP addresses.
	 *
	 * @param string $ip - The CIDR notation IP range.
	 * @return array - An array of individual IP addresses within the range.
	 */
	private function expandCIDR($ip) {
		list($subnet, $bits) = explode('/', $ip);

		$ips = [];
		if (strpos($subnet, ':') !== false) {
			// IPv6 range expansion
			$subnetDec = gmp_init(bin2hex(inet_pton($subnet)) , 16);
			$maskDec = gmp_sub(gmp_pow(2, 128) , 1);
			$maskDec = gmp_xor($maskDec, gmp_sub(gmp_pow(2, 128 - $bits) , 1));

			for ($i = 0;$i < gmp_pow(2, 128 - $bits);$i++) {
				$ipDec = gmp_add($subnetDec, $i);
				$ipBin = pack('H*', gmp_strval($ipDec, 16));
				$ip = inet_ntop($ipBin);
				$ips[] = $ip;
			}
		}
		else {
			// IPv4 range expansion
			$ip = ip2long($subnet);
			$mask = - 1 << (32 - $bits);
			$network = $ip & $mask;
			$broadcast = $network | (~$mask);

			for ($ip = $network;$ip <= $broadcast;$ip++) {
				$ips[] = long2ip($ip);
			}
		}

		return $ips;
	}

	/**
	 * Check if an IP address is whitelisted based on Cloudflare IP ranges.
	 * To-Do: IPv6 Support (untested)
	 *
	 * @param string $ip - The IP address to check.
	 * @return bool - True if the IP is whitelisted, false otherwise.
	 */
	private function isIpWhitelisted($ip) {
		$cf_ips = array(
			'199.27.128.0/21',
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/12',
		);

		if (strpos($ip, ':') !== false) {
			$ipBin = inet_pton($ip);
			foreach ($cf_ips as $cf_ip) {
				list($cf_network, $subnet) = explode('/', $cf_ip);
				$cf_ipBin = inet_pton($cf_network);
				// Perform bitwise comparison of $ipBin and $cf_ipBin according to $subnet
				// ...
				
			}
		}
		else {
			if (strpos($ip, '/') !== false) {
				list($network, $subnet) = explode('/', $ip);
				$networkObject = ip2long($network);
				$ipLong = ip2long($subnet);
				$mask = ~ ((1 << (32 - $ipLong)) - 1);
				$ipRange = $networkObject & $mask;
				$ipRangeEnd = $ipRange + pow(2, (32 - $ipLong)) - 1;

				foreach ($cf_ips as $cf_ip) {
					list($cf_network, $cf_subnet) = explode('/', $cf_ip);
					$cf_networkObject = ip2long($cf_network);
					$cf_ipLong = ip2long($cf_subnet);
					$cf_mask = ~ ((1 << (32 - $cf_ipLong)) - 1);
					$cf_ipRange = $cf_networkObject & $cf_mask;
					$cf_ipRangeEnd = $cf_ipRange + pow(2, (32 - $cf_ipLong)) - 1;

					if ($ipRange >= $cf_ipRange && $ipRangeEnd <= $cf_ipRangeEnd) {
						return true; // IP range is whitelisted
						
					}
				}
			}
			else {
				// Check if the IP is whitelisted
				if (in_array($ip, $cf_ips)) {
					return true; // IP is whitelisted
					
				}
			}
		}

		// Convert IP range to an IP network object
		if (strpos($ip, '/') !== false) {
			list($network, $subnet) = explode('/', $ip);
			$networkObject = ip2long($network);
			$ipLong = ip2long($subnet);
			$mask = ~ ((1 << (32 - $ipLong)) - 1);
			$ipRange = $networkObject & $mask;
			$ipRangeEnd = $ipRange + pow(2, (32 - $ipLong)) - 1;

			foreach ($cf_ips as $cf_ip) {
				list($cf_network, $cf_subnet) = explode('/', $cf_ip);
				$cf_networkObject = ip2long($cf_network);
				$cf_ipLong = ip2long($cf_subnet);
				$cf_mask = ~ ((1 << (32 - $cf_ipLong)) - 1);
				$cf_ipRange = $cf_networkObject & $cf_mask;
				$cf_ipRangeEnd = $cf_ipRange + pow(2, (32 - $cf_ipLong)) - 1;

				if ($ipRange >= $cf_ipRange && $ipRangeEnd <= $cf_ipRangeEnd) {
					return true; // IP range is whitelisted
					
				}
			}
		}
		else {
			// Check if the IP is whitelisted
			if (in_array($ip, $cf_ips)) {
				return true; // IP is whitelisted
				
			}
		}

		return false; // IP is not whitelisted
		
	}

	/**
	 * Write unique IP addresses to a specified file.
	 *
	 * @param array $ips - An array of IP addresses to write to the file.
	 * @param string $filePath - The path to the file where IPs should be written.
	 */
	public function writeIpsToFile($ips, $filePath) {
		// Read existing IPs from the file and store them in an array
		$existingIps = [];
		$fileContents = file_get_contents($filePath);
		
		// Open the file for appending
		$file = fopen($filePath, "a");
		
		//For two variables this
		/*preg_match_all("/deny (\S+); # (\S+)/", $fileContents, $matches, PREG_SET_ORDER);
		foreach ($matches as $match) {
			$existingIps[$match[1]] = $match[2]; // Store IP as key and source URL as value
			
		}
		// Write the unique IPs to the file
		foreach ($ips as $ipData) {
			$ip = $ipData['clientIP'];
			if (!isset($existingIps[$ip])) {
				$listUrl = $ipData['blsource'];
				//fwrite($file, "\ndeny " . $ip . "; # " . $listUrl);
				fwrite($file, "deny " . $ip . ";\n");
				$existingIps[$ip] = $listUrl; // Update the existing IPs array
				
			}
		}*/
		//For only one, this 
		preg_match_all("/deny ([\w.:]+);/i", $fileContents, $matches);
		$existingIps = $matches[1];

		foreach ($ips as $ipData) {
			$ip = $ipData['clientIP'];
			if (!in_array($ip, $existingIps)) {
				fwrite($file, "deny " . $ip . ";\n");
				$existingIps[] = $ip; // Update the existing IPs array
			}
		}

		fclose($file);
	}

}

?>
