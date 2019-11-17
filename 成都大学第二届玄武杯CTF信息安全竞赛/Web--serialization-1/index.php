<?php
error_reporting(0);
class Test
{
    private $a = 'nothing';

    public function __destruct()
    {
        if($this->a != 'nothing') {

            highlight_file('flag.php');
        }
        else {
            echo 'No Flag!';
        }
    }
}

if(isset($_GET['data'])) {
    unserialize($_GET['data']);
}
else {
    highlight_file(__FILE__);
}