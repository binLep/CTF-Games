 <?php
include('flag.php');
$f1 = @$_GET['f1'];
$f2 = @$_POST['f2'];
$f3 = @$_COOKIE['f3'];

if($f2 !== '0') {
    echo 'no';
}
else {
    if($f1 == 0 and $f1 !== 0) {
        $f2 == $f3;
        if(md5($f2) == 0 and $f2 == 0) {
            echo $flag;
        }
    }
}
highlight_file(__FILE__); 
?>