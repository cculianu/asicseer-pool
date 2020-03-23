<?php

include("functions.php");

$account = clean_account($_GET['account']);

header("Location: https://asicseer.net/user/$account");

?>
