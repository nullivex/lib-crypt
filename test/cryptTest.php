<?php
/**
 *  OpenLSS - Lighter Smarter Simpler
 *
 *	This file is part of OpenLSS.
 *
 *	OpenLSS is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU Lesser General Public License as
 *	published by the Free Software Foundation, either version 3 of
 *	the License, or (at your option) any later version.
 *
 *	OpenLSS is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU Lesser General Public License for more details.
 *
 *	You should have received a copy of the 
 *	GNU Lesser General Public License along with OpenLSS.
 *	If not, see <http://www.gnu.org/licenses/>.
 */
require_once(dirname(__DIR__).'/vendor/autoload.php');
require('lss_boot.php');
use \LSS\Crypt;

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
