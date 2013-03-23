<?php
require_once(dirname(__DIR__).'/vendor/autoload.php');
require('boot.php');
ld('crypt');

define('CRYPT_KEY','fDCb/LbbHHktg07zvZgLniX5Bf4gpmLv1LkM6nLuPNk=');
define('CRYPT_IV','mhKxiKdTSD4BKR26L/QHSnaCk/1xt1vQVD1xxE37Mew=');
define('TEST_STRING','this is the test string to encrypt');

class CryptTest extends PHPUNIT_Framework_TestCase {

	static $crypted_string = null;

	protected $crypt = false;

	protected function setUp(){
		$this->crypt = Crypt::_get(CRYPT_KEY,CRYPT_IV);
		self::$crypted_string = $this->crypt->encrypt(TEST_STRING);
	}

	protected function tearDown(){
		$this->crypt = false;
		self::$crypted_string = null;
	}

	public function testVerify(){
		$this->assertTrue(is_object($this->crypt->verify()));
	}

	public function testEncrypt(){
		$this->assertEquals(self::$crypted_string,$this->crypt->encrypt(TEST_STRING));
	}

	public function testDecrypt(){
		$this->assertEquals(TEST_STRING,$this->crypt->decrypt(self::$crypted_string));
	}

	public function testEncryptWOBase64(){
		self::$crypted_string = base64_decode(self::$crypted_string);
		$this->assertEquals(self::$crypted_string,$this->crypt->encrypt(TEST_STRING,false));
	}

	public function testDecryptWOBase64(){
		self::$crypted_string = base64_decode(self::$crypted_string);
		$this->assertEquals(TEST_STRING,$this->crypt->decrypt(self::$crypted_string,false));
	}

}
