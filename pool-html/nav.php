<?php

function navigation(){

global $_SERVER;

$pages['home'] = "/";
$pages['poolinfo'] = "/page/poolinfo";
$pages['pools'] = "/page/pools";
$pages['splns'] = "/page/splns";

$uri = $_SERVER['REQUEST_URI'];

foreach($pages as $name => $location){

        if($uri == $location || $uri == $location."/"){
                $b1 = "<b>"; $b2 = "</b>";
        } else {
                $b1 = ""; $b2 = "";
        }

        $final[] = "$b1<a href=\"$location\">$name</a>$b2\n";


}

$string = implode(" &middot; ",$final);

return $string;

}

echo navigation();

?>
