lib-crypt
=========

Shorthand library for using AES encryption provided by PHP-Mcrypt

Usage
----
```php
use \LSS\Crypt;

//create keys
$iv_key = Crypt::IVCreate();
$crypt_key = Crypt::keyCreate();

$crypt = Crypt::_get($crypt_key,$iv_key);
$crypted_str = $crypt->encrypt('my string'); //returns base64 encoded crypted string
$var = $crypt->decrypt($crypted_str); //returns 'my string'
```
Padding
----
By default MCrypt will NULL-PAD strings to get the proper encryption.
However this creates problems when expecting exact payload encryption (such as binary)

Crypt deals with this by storing the size of the payload as the first 4 bytes in the returned string
Crypt then extracts this size and trims the payload to the original size upon decrypt

The downside to this is that it cant be decrypted by the regular MCrypt functions without first
stripping the initial 4 bytes. It would be recommended to trim the payload if possible

Reference
----

### (string) Crypt::IVCreate()
Returns a proper initialization vector for the encryption type

### (string) Crypt::keyCreate()
Returns a proper secret key for the encryption type

### (object) Crypt::_get($key,$iv)
Shorthand for the construct that returns the new object

### (object) Crypt::setKey($key)
Change the key at runtime
Returns $this so its chainable

### (object) Crypt::setIV($iv)
Change the IV at runtime
Returns $this so its chainable

### (object) Crypt::verify()
Verifies the key and IV
Will throw exceptions on errors
Returns $this so its chainable

### (string) Crypt::encrypt($plain_string,$base64_encode=true)
  * $plain_string		String to be encrypted
  * $base64_encode		TRUE to base64_encode the encrypted string
Returns the encrypted and optionally base64_encoded string

### (string) Crypt::decrypt($enc_string,$base64_decode=true)
  * $enc_string			The encrypted string to be decrypted
  * $base64_decode		If the $enc_string is base64_encoded set to TRUE
Returns the EXACT original string

