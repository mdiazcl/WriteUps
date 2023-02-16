<?
$k="80e32263";
$kh="6f8af44abea0";
$kf="351039f4a7b5";
$p="0UlYyJHG87EJqEz6";

function x($t,$k){
    $c=strlen($k);
    $l=strlen($t);
    $o=""; for($i=0;$i<$l;){
        for($j=0;($j<$c&&$i<$l);$j++,$i++){
            $o .= $t[$i] ^ $k[$j];
        }
    }
    
    return $o;
}

function decode_request($encoded_request){
    $m = "";
    preg_match("/6f8af44abea0(.+)351039f4a7b5/", $encoded_request, $m);
    $command_requested = gzuncompress(x(base64_decode($m[1]), "80e32263"));
    return $command_requested;
}

function decode_response($encoded_response){
    $m = "";
    preg_match("/0UlYyJHG87EJqEz66f8af44abea0(.+)351039f4a7b5/", $encoded_response, $m);
    $r_decoded = gzuncompress(x(base64_decode($m[1]), "80e32263"));
    return $r_decoded;
}

$request = "ATTACKER_REQUEST_HERE";
$response = "SERVER_RESPONSE_HERE";

$question = decode_request($request);
$answer = decode_response($response);

# Get conversation
echo "
> Client request: $question
> Server response: $answer
";

?>