<?php

if($account){
	$short_account = substr($account,0,8)."...";
	$title = "$short_account ASICseer.net";
}
if($page){
	$title = "$page : ASICseer.net";
}

if(!$title){
	$title = "ASICseer.net";
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
<title><?php echo $title; ?></title>
<link rel="stylesheet" href="https://asicseer.net/style.css" type="text/css">
<link rel="icon" type="image/png" href="https://asicseer.net/favicon.png">
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
</head>
<body>

<div class="centered" style="max-width:760px">
        <a href="https://asicseer.net"><img alt="ASICseer logo" src="https://asicseer.com/images/asicseer.png" style="max-width:80px;margin-right:1em;"></a>

<?php include("nav.php"); ?>

</div>

        <div class="centered content-decoration">
