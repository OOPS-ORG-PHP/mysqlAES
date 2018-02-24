<?php
require_once 'mysqlAES.php';

use oops\Encrypt\mysqlAES as myAES;

$cipher = '123123 궁중 떡뽁이';
$keys = array (
	'128' => '0123456789012345',
	'192' => '012345678901234567890123',
	'256' => '01234567890123456789012345678901'
);

try {
	printf ('Original Data     : %s' . PHP_EOL, $cipher);
	printf ("Expected Data     :\n");
	printf ("           128bit : E788F1C5FB172B546DA83BAE78D2E07863263129FA8539C443B35512CF8447E4\n");
	printf ("           192bit : 08DBCABD2875EAC628630EF2033CABBE72C8E13D7197B9EE8F6845336A9C0806\n");
	printf ("           256bit : DAE591EE85369CBFF489FBB2E791934ACD14329CC94D756D3A26B119AC7C9DC5\n");

	foreach ( $keys as $key => $enckey) {
		echo "------------------------------------------------------------------------------------\n";
		$enc = myAES::hex (myAES::encrypt ($cipher, $enckey));
		printf ('%d bit encryption: %s' . PHP_EOL, $key, $enc);
		printf ('%d bit key length: %d' . PHP_EOL, $key, strlen ($enckey));
		printf ('%d bit hex length: %d' . PHP_EOL, $key, strlen ($enc));
		$dec = myAES::decrypt (myAES::unhex ($enc), $enckey);
		printf ('%d bit revoke    : %s' . PHP_EOL, $key, $dec);
	}
} catch ( Exception $e ) {
    fprintf (STDERR, "%s\n", $e->getMessage ());
	print_r ($e->getTrace ()) . "\n";
}

?>
