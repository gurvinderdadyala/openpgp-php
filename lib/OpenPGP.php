<?php
// This is free and unencumbered software released into the public domain.
/**
 * OpenPGP.php is a pure-PHP implementation of the OpenPGP Message Format
 * (RFC 4880).
 *
 * @package OpenPGP
 * @author  Arto Bendiken <arto.bendiken@gmail.com>
 * @author  Stephen Paul Weber <singpolyma@singpolyma.net>
 * @author  Deon George <deon@leenooks.net>
 * @see     http://github.com/bendiken/openpgp-php
 */

namespace Leenooks;

use Illuminate\Support\Arr;
use phpseclib\Crypt\RSA as Crypt_RSA;

use Leenooks\OpenPGP\Exceptions\PacketTagException;

/**
 * @see http://tools.ietf.org/html/rfc4880
 */
class OpenPGP
{
	const VERSION = [0,5,0];
	private $key = NULL;

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-12.2
	 */
	static function bitlength($data)
	{
		return (strlen($data) - 1) * 8 + (int)floor(log(ord($data[0]), 2)) + 1;
	}

	/**
	 * Create a PGP Key
	 *
	 * @todo Incomplete and untested.
	 *
	 * @param string $name
	 * @param string $email
	 * @param string $comment
	 * @param int $keysize
	 * @return OpenPGP
	 */
	static function create(string $name,string $email,string $comment,int $keysize=512): self
	{
		$result = new self;

		$rsa = new Crypt_RSA;
		$rsa->loadKey(Arr::get($rsa->createKey($keysize),'privatekey'));

		$nkey = new OpenPGP\SecretKeyPacket(array(
			'n' => $rsa->modulus->toBytes(),
			'e' => $rsa->publicExponent->toBytes(),
			'd' => $rsa->exponent->toBytes(),
			'p' => $rsa->primes[2]->toBytes(),
			'q' => $rsa->primes[1]->toBytes(),
			'u' => $rsa->coefficients[2]->toBytes()
		));

		$wkey = new OpenPGP\Crypt\RSA($nkey);

		$uid = new OpenPGP\UserIDPacket($name,$comment,$email);

		$result->key = $wkey->sign_key_userid([$nkey,$uid]);

		return $result;
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-6
	 * @see http://tools.ietf.org/html/rfc4880#section-6.1
	 */
	static function crc24($data): int
	{
		$crc = 0x00b704ce;

		for ($i = 0; $i < strlen($data); $i++) {
			$crc ^= (ord($data[$i]) & 255) << 16;

			for ($j = 0; $j < 8; $j++) {
				$crc <<= 1;
				if ($crc & 0x01000000) {
					$crc ^= 0x01864cfb;
				}
			}
		}

		return $crc & 0x00ffffff;
	}

	static function decode_s2k_count($c)
	{
		return ((int)16 + ($c & 15)) << (($c >> 4) + 6);
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-6
	 * @see http://tools.ietf.org/html/rfc4880#section-6.2
	 * @see http://tools.ietf.org/html/rfc2045
	 */
	static function enarmor($data,$marker='MESSAGE',array $headers=[])
	{
		$text = self::header($marker)."\n";

		foreach ($headers as $key => $value) {
			$text .= $key.': '.(string)$value."\n";
		}

		$text .= "\n".wordwrap(base64_encode($data),76,"\n",true);
		$text .= "\n".'='.base64_encode(substr(pack('N',self::crc24($data)),1))."\n";
		$text .= self::footer($marker)."\n";

		return $text;
	}

	static function encode_s2k_count($iterations)
	{
		if($iterations >= 65011712) return 255;

		$count = $iterations >> 6;
		$c = 0;

		while($count >= 32) {
			$count = $count >> 1;
			$c++;
		}
		$result = ($c << 4) | ($count - 16);

		if (OpenPGP::decode_s2k_count($result) < $iterations) {
			return $result + 1;
		}

		return $result;
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-6.2
	 */
	static protected function footer($marker): string
	{
		return'-----END '.strtoupper((string)$marker).'-----';
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-6.2
	 */
	static protected function header($marker): string
	{
		return '-----BEGIN '.strtoupper((string)$marker).'-----';
	}

	/**
	* @see http://tools.ietf.org/html/rfc4880#section-6
	* @see http://tools.ietf.org/html/rfc2045
	*/
	static function unarmor($text,$header='PGP PUBLIC KEY BLOCK')
	{
		$header = self::header($header);

		$text = str_replace(["\r\n","\r"],["\n",''],$text);

		if (($pos1=strpos($text,$header)) !== FALSE
			&& ($pos1=strpos($text,"\n\n",$pos1+=strlen($header))) !== FALSE
			&& ($pos2=strpos($text,"\n=",$pos1+=2)) !== FALSE)
		{
			return base64_decode($text=substr($text,$pos1,$pos2-$pos1));
		}
	}
}