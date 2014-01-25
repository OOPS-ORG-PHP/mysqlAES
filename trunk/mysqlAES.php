<?php
/**
 * Project: mysqlAES :: MYSQL 호환 AES ENCRYPT/DECRYPT Class<br>
 * File:    mysqlAES.php
 *
 * mysqlAES 패키지는 MySQL의 AES_EMCRYPT, AES_DECRYPT, HEX, UNHEX 함수를
 * php에서 호환되게 사용할 수 있도록 하는 기능을 제공한다.
 *
 * encrypt method와 decrypt method의 경우, key 길이가 128bit(16byte)이면
 * MySQL과 MariaDB의 AES_ENCRYPT/AES_DECRYPT 함수와 완벽하게 호환이 된다.
 *
 * key 길이가 192또는 256bit일 경우에는 oops에서 제공하는 lib_mysqludf_aes256
 * UDF에서 제공하는 AES256_ENCRYPT, AES256_DECRYPT와 완변하게 호환이 된다.
 *
 * 예제:
 * {@example pear_mysqlAES/test.php}
 *
 *
 * @category    Encryption
 * @package     mysqlAES
 * @author      JoungKyun.Kim <http://oops.org>
 * @copyright   (c) 2014 OOPS.org
 * @license     BSD License
 * @version     SVN: $Id$
 * @link        http://pear.oops.org/package/mysqlAES
 * @since       File available since release 0.0.1
 * @example     pear_mysqlAES/test.php mysqlAES 예제
 * @filesource
 *
 */

/**
 * import oops/myException class
 */
@require_once 'myException.php';
mysqlAES_REQUIRES ();

set_error_handler('myException::myErrorHandler');

/**
 * mysqlAES 패키지는 MySQL의 AES_EMCRYPT, AES_DECRYPT, HEX, UNHEX 함수를
 * php에서 호환되게 사용할 수 있도록 하는 기능을 제공한다.
 *
 * encrypt method와 decrypt method의 경우, key 길이가 128bit(16byte)이면
 * MySQL과 MariaDB의 AES_ENCRYPT/AES_DECRYPT 함수와 완벽하게 호환이 된다.
 *
 * key 길이가 192또는 256bit일 경우에는 oops에서 제공하는 lib_mysqludf_aes256
 * UDF에서 제공하는 AES256_ENCRYPT, AES256_DECRYPT와 완변하게 호환이 된다.
 *
 * 예제:
 * {@example pear_mysqlAES/test.php}
 *
 * @package mysqlAES
 */
Class mysqlAES {
	// {{{ properties
	/**
	 * AES block 사이즈
	 */
	const AES_BLOCK_SIZE = 16;
	// }}}

	// {{{ +-- public __construct (void)
	/**
	 * mysqlAES 초기화
	 *
	 * @access public
	 */
	function __construct () { }
	// }}}

	// {{{ +-- static public (string) hex ($v)
	/**
	 * Return a hexadecimal representation of a decimal or string value
	 *
	 * This method is compatible HEX function of mysql
	 *
	 * Example:
	 * {@example pear_mysqlAES/test.php 16 1}
	 *
	 * @access public
	 * @return string hexadecimal data
	 * @param  string original data
	 */
	static public function hex ($v) {
		return strtoupper (bin2hex ($v));
	}
	// }}}

	// {{{ +-- static public (string) unhex ($v)
	/**
	 * Return a string containing hex representation of a number
	 *
	 * This method is compatible UNHEX function of mysql
	 *
	 * Example:
	 * {@example pear_mysqlAES/test.php 19 1}
	 *
	 * @access public
	 * @return string
	 * @param  string hexadecimal data
	 */
	static public function unhex ($v) {
		return self::hex2bin ($v);
	}
	// }}}

	// {{{ +-- static public (string) encrypt ($cipher, $key)
	/**
	 * Encrypt using AES
	 *
	 * This method is compatible AES_ENCRYPT function of mysql, if key is 128 bit.
	 * And then, If key is 192 or 256 bit, this method is compatible follow APIS:
	 *  - {@link http://mirror.oops.org/pub/oops/mysql/lib_mysqludf_aes256/ MySQL UDF lib_mysqludf_aes256}
	 *  - {@link http://mirror.oops.org/pub/oops/javascript/mysqlAES/ Javascript mysqlAES class}
	 *
	 * Example:
	 * {@example pear_mysqlAES/test.php}
	 *
	 * @access public
	 * @return string encrypted data by AES
	 * @param  string data for being encryption
	 * @param  string encryption key
	 *   - 128bit : 16 byte string
	 *   - 192bit : 24 byte string
	 *   - 256bit : 32 byte string
	 */
	static public function encrypt ($cipher, $key) {
		if ( ! $cipher || ! $key )
			return null;

		$blocks = self::AES_BLOCK_SIZE * (floor (strlen ($cipher) / self::AES_BLOCK_SIZE) + 1);
		$padlen = $blocks - strlen ($cipher);

		$cipher .= str_repeat (chr ($padlen), $padlen);

		return mcrypt_encrypt (MCRYPT_RIJNDAEL_128, $key, $cipher, MCRYPT_MODE_ECB);
	}
	// }}}

	// {{{ +-- static public (string) decrypt ($cipher, $key)
	/**
	 * Decrypt using AES
	 *
	 * This method is compatible AES_DECRYPT function of mysql, if key is 128 bit
	 * And then, If key is 192 or 256 bit, this method is compatible follow APIS:
	 *  - {@link http://mirror.oops.org/pub/oops/mysql/lib_mysqludf_aes256/ MySQL UDF lib_mysqludf_aes256}
	 *  - {@link http://mirror.oops.org/pub/oops/javascript/mysqlAES/ Javascript mysqlAES class}
	 *
	 * Example:
	 * {@example pear_mysqlAES/test.php}
	 *
	 * @access public
	 * @return string decrypted data by AES
	 * @param  string cipher data for being decryption
	 * @param  string decryption key
	 *   - 128bit : 16 byte string
	 *   - 192bit : 24 byte string
	 *   - 256bit : 32 byte string
	 */
	static public function decrypt ($cipher, $key) {
		if ( ! $cipher || ! $key )
			return null;

		$r = mcrypt_decrypt (MCRYPT_RIJNDAEL_128, $key, $cipher, MCRYPT_MODE_ECB);
		$last = $r[strlen ($r) - 1];
		$r = substr ($r, 0, strlen($r) - ord($last));
		return $r;
	}
	// }}}

	// {{{ +-- private (string) hex2bin ($v)
	/**
	 * Decodes a hexadecimally encoded binary string
	 *
	 * Support hex2bin function if php version is less than 5.4.0.
	 *
	 * @access public
	 * @return string Returns the binary representation of the given data or FALSE on failure.
	 * @param  string Hexadecimal representation of data.
	 */
	private function hex2bin ($v) {
		if ( function_exists ('hex2bin') )
			return hex2bin ($v);

		if ( ! is_string ($v) )
			return null;

		$len = strlen ($v);
		for ( $i=0; $i<$len; $i+=2 ) {
			$r .= chr (hexdec ($v{$i} . $v{($i+1)}));
		}

		return $r;
	}
	// }}}
}

// {{{ +-- public mysqlAES_REQUIRES (void)
/**
 * mysqlAES 패키지에서 필요한 의존성을 검사한다.
 *
 * @access public
 * @return void
 */
function mysqlAES_REQUIRES () {
	if ( ! class_exists ('myException') ) {
		$br = PHP_EOL;
		if ( PHP_SAPI != 'cli' )
			$br = '<br>' . PHP_EOL;
		$brbr = $br . $br;

		$msg = sprintf (
			$brbr .
			'-------------------------------------------------' . $brbr .
			'mysqlAES ERROR!' . $brbr .
			'mysqlAES class needs oops/myException pear package' . $br .
			'You can get myException pear package at' . $br .
			'http://mirror.oops.org/pub/oops/php/pear/myException/' . $br .
			'Also you can install with pear command as follow command' . $br .
			'shell> pear channel-discover pear.oops.org' . $br .
			'shell> pear install oops/myException' . $brbr .
			'-------------------------------------------------' . $brbr
		);
		throw new Exception ($msg, E_USER_ERROR);
	}

	if ( ! extension_loaded ('mcrypt') ) {
		throw new myException ('mysqlAES class need mcrypt extension', E_USER_ERROR);
	}
}
// }}}

?>
