<?php

include("/var/www/html/functions.php");

$file = "/var/www/pool-master-vultr-ord-prod/pool/pool.status";
$pool_statuses = file($file,FILE_IGNORE_NEW_LINES);

foreach($pool_statuses as $pool_status){
	$array[] = json_decode($pool_status,TRUE);
}

echo "<h2>Pool Status</h2>";
echo "<pre>";
print_r($array);
echo "</pre>";

?>

