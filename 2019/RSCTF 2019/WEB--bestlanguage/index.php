<?php
error_reporting(E_ERROR); 
ini_set("display_errors","Off");
highlight_file(__FILE__);
class yemoli {
    protected $alive;
    function __wakeup() {
        $this->alive = 'phpinfo();';
    }
    function __construct() {
        $this->alive = new good();
    }
    function __destruct() {
        $this->alive->action();
    }
}
class good {
    function action() {
        echo "I am a good boy!";
    }
}
class bad {
    private $code;
    function action() {
        eval($this->code);
    }
}
unserialize($_GET['string']);
