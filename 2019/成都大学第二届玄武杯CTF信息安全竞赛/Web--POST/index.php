<?php
error_reporting(0);
include('flag.php');
if($_GET['p1'] == '' or $_GET['p2'] == '') {
    header('location: index.php?p1=CDUSEC&p2=CTF');
}

highlight_file('index.php');
print $_GET['p1'];
print '<br>';
print $_GET['p2'];
print '<br>';

if($_POST['p4'] === 'flag') {
    print $flag;
} 