--TEST--
Test frozen services
--SKIPIF--
<?php if (!extension_loaded("pimple")) print "skip"; ?>
--FILE--
<?php 
$p = new Pimple\Container();
$p[42] = 'foo';
$p[42] = 'bar';

$p['foo'] = function () { return 1; };
$p['foo'] = function () { return 2; };

$a = $p['foo'];
var_dump($a);

try {
	$p['foo'] = function () { };
	echo "Exception excpected 1\n";
} catch (RuntimeException $e) {
	echo $e->getMessage(), "\n";
}

$p[42] = function() { return 3; };
$a = $p[42];
var_dump($a);

try {
	$p[42] = function () { };
	echo "Exception excpected 2\n";
} catch (RuntimeException $e) {
	echo $e->getMessage(), "\n";
}
?>
--EXPECTF--
int(2)
Cannot override frozen service "foo".
int(3)
Cannot override frozen service "42".
