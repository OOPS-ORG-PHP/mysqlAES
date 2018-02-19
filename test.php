<?php
require_once 'mysqlAES.php';

use oops\Encrypt\mysqlAES as myAES;

#mysqlAES::$extname = 'openssl';
echo "Extension Type:: " . myAES::$extname . "\n\n";

$cipher = '123123 궁중 떡뽁이';
$keys = array (
	'128' => '0123456789012345',
	'192' => '012345678901234567890123',
	'256' => '01234567890123456789012345678901'
);

try {
	printf ('Original Data     : %s' . PHP_EOL, $cipher);

	foreach ( $keys as $key => $val ) {
		echo "------------------------------------------------------------------------------------\n";
		$enc = myAES::hex (myAES::encrypt ($cipher, $val));
		printf ('%d bit encryption: %s' . PHP_EOL, $key, $enc);
		printf ('%d bit key length: %d' . PHP_EOL, $key, strlen ($val));
		printf ('%d bit hex length: %d' . PHP_EOL, $key, strlen ($enc));
		$dec = myAES::decrypt (myAES::unhex ($enc), $val);
		printf ('%d bit revoke    : %s' . PHP_EOL, $key, $dec);
	}
} catch ( Exception $e ) {
    fprintf (STDERR, "%s\n", $e->getMessage ());
	print_r ($e->getTrace ()) . "\n";
}

?>
