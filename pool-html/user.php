<?php

include("/var/www/html/functions.php");

$account = $_GET['account'];

$path = "/var/www/pool-master-vultr-ord-prod/users/";

$file = $path.clean_account($account);

if(file_exists($file)){
	$json_data = file_get_contents($file);
	$array = json_decode($json_data,TRUE);
} else {
	$array = array("no such user");
}

include("top.php");

echo "<pre>";
echo "This will be the user page.

";
print_r($array);
echo "</pre>";

include("bottom.php");

?>
