<?php
declare (strict_types=1);
declare (encoding='UTF-8');

/**
 * Project: oops\Encrypt\mysqlAES :: MYSQL 호환 AES ENCRYPT/DECRYPT Class<br>
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
 * 의존성:
 * <ul style="margin-left: 30px;">
 *    <li>php >= 7.1<br>
 *        PHP 7.1 이전 버전에서는 1.0 branch 를 사용하십시오.</li>
 *    <li>openssl extension</li>
 * </ul>
 *
 * 예제:
 * {@example mysqlAES/test.php}
 *
 *
 * @category    Encryption
 * @package     mysqlAES
 * @author      JoungKyun.Kim <http://oops.org>
 * @copyright   (c) 2018, OOPS.org
 * @license     BSD License
 * @link        http://pear.oops.org/package/mysqlAES
 * @since       File available since release 0.0.1
 * @example     mysqlAES/test.php mysqlAES 예제
 * @filesource
 *
 */
namespace oops\Encrypt;

mysqlAES_REQUIRES ();

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
 * {@example mysqlAES/test.php}
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
	 * oops\Encrypt\mysqlAES 초기화
	 *
	 * @access public
	 */
	function __construct () { }
	// }}}

	// {{{ +-- static public (string) hex (string $v = null)
	/**
	 * Return a hexadecimal representation of a decimal or string value
	 *
	 * This method is compatible HEX function of mysql
	 *
	 * Example:
	 * {@example mysqlAES/test.php 22 1}
	 *
	 * @access public
	 * @return string hexadecimal data. If given parameter $v is empty, return null.
	 * @param  string original data
	 */
	static public function hex (?string $v): ?string {
		if ( ! $v )
			return null;
		return strtoupper (bin2hex ($v));
	}
	// }}}

	// {{{ +-- static public (string) unhex (string $v = null)
	/**
	 * Return a string containing hex representation of a number
	 *
	 * This method is compatible UNHEX function of mysql
	 *
	 * Example:
	 * {@example mysqlAES/test.php 26 1}
	 *
	 * @access public
	 * @return string Returns an ASCII string containing the hexadecimal representation.
	 *                If given parameter $v is empty, return null.
	 * @param  string hexadecimal data
	 */
	static public function unhex (?string $v): ?string {
		if ( ! $v || ! is_string ($v) )
			return null;

		$r = hex2bin ($v);
		return !$r ? null : $v;
	}
	// }}}

	// {{{ +-- static private (string) _encrypt (string $cipher, string $key)
	/**
	 * skeleton encrypt function
	 * @access private
	 * @return string encrypted data by AES
	 * @param  string The plaintext message data to be encrypted. 
	 * @param  string The key for encryption
	 */
	static private function _encrypt (string $cipher, string $key): ?string {
		$keylen = strlen ($key);
		if ( $keylen <= 16 )
			$method = 'AES-128-ECB';
		else if ( $keylen <= 24 )
			$method = 'AES-192-ECB';
		else
			$method = 'AES-256-ECB';
		return openssl_encrypt ($cipher, $method, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
	}
	// }}}

	// {{{ +-- static public (string) encrypt (string $cipher = null, string $key = null)
	/**
	 * Encrypt using AES
	 *
	 * This method is compatible AES_ENCRYPT function of mysql, if key is 128 bit.
	 * And then, If key is 192 or 256 bit, this method is compatible follow APIS:
	 *  - {@link http://mirror.oops.org/pub/oops/mysql/lib_mysqludf_aes256/ MySQL UDF lib_mysqludf_aes256}
	 *  - {@link http://mirror.oops.org/pub/oops/javascript/mysqlAES/ Javascript mysqlAES class}
	 *
	 * Example:
	 * {@example mysqlAES/test.php}
	 *
	 * @access public
	 * @return string encrypted data by AES. If $cipyer or $key has empty value, return null
	 * @param  string The plaintext message data to be encrypted. 
	 * @param  string encryption key
	 *   - 128bit : 16 byte string
	 *   - 192bit : 24 byte string
	 *   - 256bit : 32 byte string
	 */
	static public function encrypt (?string $cipher, ?string $key): ?string {
		if ( ! $cipher || ! $key )
			return null;

		$blocks = self::AES_BLOCK_SIZE * (floor (strlen ($cipher) / self::AES_BLOCK_SIZE) + 1);
		$padlen = (int) $blocks - strlen ($cipher);

		$cipher .= str_repeat (chr ($padlen), $padlen);

		$r = self::_encrypt ($cipher, $key);
		return !$r ? null : $r;
	}
	// }}}

	// {{{ +-- static private (string) _decrypt (string $cipher, string $key)
	/**
	 * skeleton encrypt function
	 * @access private
	 * @return string encrypted data by AES
	 */
	static private function _decrypt (string $cipher, string $key): ?string {
		$keylen = strlen ($key);
		if ( $keylen <= 16 )
			$method = 'AES-128-ECB';
		else if ( $keylen <= 24 )
			$method = 'AES-192-ECB';
		else
			$method = 'AES-256-ECB';
		return openssl_decrypt ($cipher, $method, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
	}
	// }}}

	// {{{ +-- static public (string) decrypt (string $cipher = null, string $key = null)
	/**
	 * Decrypt using AES
	 *
	 * This method is compatible AES_DECRYPT function of mysql, if key is 128 bit
	 * And then, If key is 192 or 256 bit, this method is compatible follow APIS:
	 *  - {@link http://mirror.oops.org/pub/oops/mysql/lib_mysqludf_aes256/ MySQL UDF lib_mysqludf_aes256}
	 *  - {@link http://mirror.oops.org/pub/oops/javascript/mysqlAES/ Javascript mysqlAES class}
	 *
	 * Example:
	 * {@example mysqlAES/test.php}
	 *
	 * @access public
	 * @return string decrypted data by AES. If $cipyer or $key has empty value, return null.
	 * @param  string cipher data for being decryption
	 * @param  string decryption key
	 *   - 128bit : 16 byte string
	 *   - 192bit : 24 byte string
	 *   - 256bit : 32 byte string
	 */
	static public function decrypt (?string $cipher, ?string $key): ?string {
		if ( ! $cipher || ! $key )
			return null;

		if ( ! ($r = self::_decrypt ($cipher, $key)) )
			return null;
		$last = $r[strlen ($r) - 1];
		$r = substr ($r, 0, strlen($r) - ord($last));
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
	if ( ! extension_loaded ('openssl') ) {
		throw new \Exception (
			__NAMESPACE__ . '\mysqlAES class must need openssl extension',
			E_USER_ERROR
		);
	}
}
// }}}

?>
