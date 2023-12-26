<?php
require_once('loganalyzer.class.php');
/**
 * Sorry for the unsorted goodness!
 * Below lies several demonstrations of uses.
 *
 */

/* Initialize the LogAnalyzer with the log file path */
$logFile = 'nginxlogs.log';
$log = new LogAnalyzer($logFile);

/* Save Suspicious IPs to File */
$craa = $log->checkSuspiciousLogs('clientIP,requestDetails', true);
$log->writeIpsToFile($craa, '/var/www/bans.log');
echo "\r\n<br/>Saved to file.";
//print_r($craa);
/*
 *
*/

/* Count how many lines of Parsed Log Data we have; Useful for seeing if all nginx log entries were parsed or not! */
$numberOfLines = count($log->logData);
echo "\r\n<br/>Total number of logged lines: $numberOfLines";

/* Search log data for entries matching a specific field and value. */
$searchField = 'clientIP';
$searchValue = '1.1.1.1';
//$searchResults = $log->searchLogs($searchField, $searchValue);
//print_r(($searchResults));
// Search by date/time range
$start = new DateTime('2022-01-01 00:00:00', new DateTimeZone('UTC'));
$end = new DateTime('2024-12-31 23:59:59', new DateTimeZone('UTC'));

/*Process log data and calculate the frequency of a specified field's values for each day. */
//print_r($log->calculateFieldFrequencyByDay('clientIP'));
/* Search log data for entries within a specified time period. */
//$timeSearchResults = $log->searchLogsByTimePeriod($start, $end);
//print_r($timeSearchResults);
/* Search log data for entries that match a specified key-value pair. */
//$keyValueSearchResults = $log->searchLogsByKeyValue('clientIP', '1.1.1.1');
//print_r($keyValueSearchResults);
/* Search log data for entries that match a specified time range and key-value pair. */
//$timeKeyValueSearchResults = $log->searchLogsByTimeAndKeyValue($start, $end, 'clientIP', '1.1.1.1');
//print_r($timeKeyValueSearchResults);
/* Count the number of log entries that match a specified key-value pair. */
//$count = $log->countVisitsByKeyValue('clientIP', '1.1.1.1');
/* Get a list of visited pages that match a specified key-value pair. */
//$pages = $log->visitedPagesByKeyValue('clientIP', '1.1.1.1');
/* Get the frequency of values in a specified log field */
//print_r($log->getFrequencyOfField('clientIP'));


?>