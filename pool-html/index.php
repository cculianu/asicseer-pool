<?php

$pages[] = "home";
$pages[] = "home-dev";
$pages[] = "splns";
$pages[] = "pools";
$pages[] = "poolinfo";
$pages[] = "miners-938571956181358351751";


$page = str_replace("/","",$_GET['page']);

if(!$page){ $page = "home"; }

if(in_array($page,$pages)){
        $page_include = "/var/www/html/pages/".$page.".php";
} else {
        $page_include = "/var/www/html/pages/home.php";
}

include("top.php");

include($page_include);

include("bottom.php");

?>
