<?php

include("/var/www/html/functions.php");

header("Access-Control-Allow-Origin: *");
header('Content-Type: application/json');

$account = $_GET['account'];

$path = "/var/www/pool-master-vultr-ord-prod/users/";

$file = $path.clean_account($account);

$json_data = file_get_contents($file);

$json_pretty = prettyPrint($json_data);

echo $json_pretty;

?>

