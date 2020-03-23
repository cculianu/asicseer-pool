<?php

include("/var/www/html/functions.php");

$path = "/var/www/pool-master-vultr-ord-prod/users/";

$account = $_GET['account'];

$file = $path.clean_account($account);

$json_data = file_get_contents($file);

$json_pretty = prettyPrint($json_data);

include("top.php");

echo "<pre>";
echo $json_pretty;
echo "</pre>";

include("bottom.php");

?>

