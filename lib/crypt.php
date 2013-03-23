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
namespace LSS;

if(!extension_loaded('mcrypt')) throw new Exception('MCrypt extension not present!');
//---------------------------------------------------------
//Crypt Library
//	This is a shorthand library for using AES encryption
//	on the fly
//---------------------------------------------------------

class Crypt {

	//NOTE: changing these would require new keys
	static $crypt_cipher	=	MCRYPT_RIJNDAEL_256;
	static $crypt_mode		=	MCRYPT_MODE_CBC;
	static $crypt_rand		=	MCRYPT_DEV_URANDOM;

	private $key;
	private $iv;

	protected $verified = false;

	//-----------------------------------------------------
	//Static Access
	//-----------------------------------------------------

	//generate usable IV for config
	public static function IVCreate(){
		return base64_encode(mcrypt_create_iv(
			 mcrypt_get_iv_size(self::$crypt_cipher,self::$crypt_mode)
			,self::$crypt_rand
		));
	}

	//generate usable key for config
	public static function keyCreate(){
		return base64_encode(mcrypt_create_iv(
			 mcrypt_get_key_size(self::$crypt_cipher,self::$crypt_mode)
			,self::$crypt_rand
		));
	}

	//static constructor access
	public static function _get($key,$iv){
		return new static($key,$iv);
	}

	//-----------------------------------------------------
	//Object Methods
	//-----------------------------------------------------

	//setup and store keys
	protected function __construct($key,$iv){
		$this->key = $key;
		$this->iv = $iv;
	}

	public function setKey($key){
		$this->key = $key;
		return $this;
	}

	public function setIV($iv){
		$this->iv = $iv;
		return $this;
	}

	public function verify(){
		$this->verifyKey();
		$this->verifyIV();
		$this->verified = true;
		return $this;
	}

	//verify existence and size of key
	protected function verifyKey(){
		$key_size = mcrypt_get_key_size(self::$crypt_cipher,self::$crypt_mode);
		//verify we have a key before starting
		if(!isset($this->key) || is_null($this->key)){
			throw new Exception('No encryption key defined in config');
		}
		if(strlen(base64_decode($this->key)) < $key_size){
			throw new Exception('Encryption key is too shorted, required length: '.$key_size);
		}
		return true;
	}

	//verify existencve and size of iv
	protected function verifyIV(){
		$iv_size = mcrypt_get_iv_size(self::$crypt_cipher,self::$crypt_mode);
		//verify we have a key before starting
		if(!isset($this->iv) || is_null($this->iv)){
			throw new Exception('No IV key defined in config');
		}
		if(strlen(base64_decode($this->iv)) < $iv_size){
			throw new Exception('Encryption IV is too shorted, required length: '.$iv_size);
		}
		return true;
	}

	//encrypt string and optionally base64_encode
	public function encrypt($plain_string,$base64_encode=true){
		if(!$this->verified) $this->verify();
		//add size atom to encrypted string
		$size = pack('N',strlen($plain_string));
		$plain_string = $size.$plain_string;
		//encrypt and return
		$enc_string = mcrypt_encrypt(
			 self::$crypt_cipher
			,base64_decode($this->key)
			,$plain_string
			,self::$crypt_mode
			,base64_decode($this->iv)
		);
		if($base64_encode) return base64_encode($enc_string);
		return $enc_string;
	}

	//decrypt string from an optionally base64_encoded source
	function decrypt($enc_string,$base64_decode=true){
		if(is_null($enc_string) || empty($enc_string)) return NULL;
		if(!$this->verified) $this->verify();
		//decrypt and return
		if($base64_decode) $enc_string = base64_decode($enc_string);
		$plain_string = mcrypt_decrypt(
			 self::$crypt_cipher
			,base64_decode($this->key)
			,$enc_string
			,self::$crypt_mode
			,base64_decode($this->iv)
		);
		//get size of string from atom
		$size = array_shift(unpack('N',substr($plain_string,0,4)));
		//make sure we have the original string
		$plain_string = substr($plain_string,4,$size);
		return $plain_string;
	}

}
