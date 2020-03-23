<?php

include("/var/www/html/functions.php");

$pool_miners = "/var/www/pool-master-vultr-ord-prod/pool/pool.miners";

echo "<h2>Pool Miners</h2>";

$miner_lines = file($pool_miners,FILE_IGNORE_NEW_LINES);

foreach($miner_lines as $miner){
	list($account, $json_payload) = explode(":", $miner, 2);
	echo "<h3>$account</h3>";
	echo "<pre>";
	echo prettyPrint($json_payload);

	echo "</pre>";
}

?>

