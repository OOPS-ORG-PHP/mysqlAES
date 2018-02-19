# PHP mysqlAES class library

## Abstract

***mysqlAES*** package supports **AES 128/192/256** encryptioin, and this API is compatible with [lib_mysqludf_aes256 MySQL UDF](https://github.com/Joungkyun/lib_mysqludf_aes256) and [mysqlAES javascript API](http://mirror.oops.org/pub/oops/javascript/mysqlAES/).

Also, this api supports hex and unhex API that is compatble with MySQL and MariaDB.

If encrypt with 128bit, this api is operate in the same way with AES_ENCRYPT and
AES_DECRYPT of MySQL or MariaDB.

## License

BSD 2-Clause

## Installation

mysqlAES 2.x works with PHP 7 and later. Use mysqlAES-1 branch or 1.x version for use with pre-PHP 7 versions. The ___mysqlAES-1___ branch also supports php 7.

mysqlAES package needs follow external libraries.

  1. php [mcrypt](http://php.net/manual/en/book.mcrypt.php) extension or [openssl](http://php.net/manual/en/book.openssl.php) extension
      * mcrypt extension is deprecated in PHP 7.1
      * mcrypt extension has been removed in PHP 7.2
  
And, you can install in three ways that are download source files by hands or using pear command or use composer. If you choose to install manually, you will also need to install the required external libraries yourself. Therefore, it is recommended to use the pear command to reduce this effort.

### * Download source files

1. download latest version at [release page](https://github.com/OOPS-ORG-PHP/mysqlAES/releases).
2. uncompress the downloaded package to the desired path.
3. add the path in the ***include_path*** ini option.
4. include ***mysqlAES.php*** file in your code.

### * Use pear command

This method is needed root privileges.

  ```bash
  [root@host ~]$ pear channel-discover pear.oops.org
  [root@host ~]$ pear install oops/mysqlAES
  [root@host ~]$ pear list -a
  ```

### * Use composer

first, make composer.json as follow:

  ```json
  {
      "require": {
          "joungkyun/mysqlaes": "2.*"
      }
  }
  ```

and, install mysqlAES

  ```bash
  [user@host project]$ php composer.phpt install
  Loading composer repositories with package information
  Updating dependencies (including require-dev)
  Package operations: 1 installs, 0 updates, 0 removals
    - Installing joungkyun/mysqlaes (2.0.0): Downloading (100%)
  Writing lock file
  Generating autoload files
  [user@host project]$
  ```

and, write code as follow:

  ```php
  <?php
  require_once 'vendor/autoload.php';

  echo 'mysqlAES is supported ';
  if ( class_exists ('oops\Encrypt\mysqlAES') )
      echo 'YES';
  else
      echo 'NO';

  echo "\n";
  ?>
  ```

## APIs

See also [mysqlAES reference](http://pear.oops.org/docs/mysqlAES/mysqlAES.html) page.

* oops\Encrypt\mysqlAES::hex(STRING)
* oops\Encrypt\mysqlAES::unhex(STRING)
* oops\Encrypt\mysqlAES::encrypt(STRING, KEY)
* oops\Encrypt\mysqlAES::decrypt(ENCRYPTED_STRING, KEY)

### Examples:
```php
<?php
require_once 'mysqlAES.php';

use oops\Encrypt;

$string = "123 abced\n";
$key    = '0123456789012345';
$enc = mysqlAES::hex (mysqlAES::encrypt ($string, $key));
$dec = mysqlAES::decrypt (mysqlAES::unhex ($enc), $key);
?>
```


## Reference
This class is compatible with follow APIs:

* MySQL UDF [lib_mysqludf_aes256](https://github.com/Joungkyun/lib_mysqludf_aes256)
* javascript [mysqlAES class](http://mirror.oops.org/pub/oops/javascript/mysqlAES/)
