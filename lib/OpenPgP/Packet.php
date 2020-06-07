<?php

namespace Leenooks\OpenPGP;

use Leenooks\OpenPGP\Exceptions\PacketTagException;

/**
 * OpenPGP packet.
 *
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-4.3
 */
abstract class Packet
{
	protected static $DEBUG = FALSE;
	protected $tag = NULL;
	public $size,$data;

	static protected $tags = [
		1 => 'AsymmetricSessionKey',	// Public-Key Encrypted Session Key
		2 => 'Signature',				// Signature Packet
		3 => 'SymmetricSessionKey',		// Symmetric-Key Encrypted Session Key Packet
		4 => 'OnePassSignature',		// One-Pass Signature Packet
		5 => 'SecretKey',				// Secret-Key Packet
		6 => 'PublicKey',				// Public-Key Packet
		7 => 'SecretSubkey',			// Secret-Subkey Packet
		8 => 'CompressedData',			// Compressed Data Packet
		9 => 'EncryptedData',			// Symmetrically Encrypted Data Packet
		10 => 'Marker',					// Marker Packet
		11 => 'LiteralData',			// Literal Data Packet
		12 => 'Trust',					// Trust Packet
		13 => 'UserID',					// User ID Packet
		14 => 'PublicSubkey',			// Public-Subkey Packet
		17 => 'UserAttribute',			// User Attribute Packet
		18 => 'IntegrityProtectedData',	// Sym. Encrypted and Integrity Protected Data Packet
		19 => 'ModificationDetectionCode', // Modification Detection Code Packet
		60 => 'Experimental',			// Private or Experimental Values
		61 => 'Experimental',			// Private or Experimental Values
		62 => 'Experimental',			// Private or Experimental Values
		63 => 'Experimental',			// Private or Experimental Values
	];

	static function class_for($tag)
	{
		return (isset(self::$tags[$tag]) AND class_exists($class='Leenooks\OpenPGP\\'.self::$tags[$tag].'Packet'))
			? $class
			: __CLASS__;
	}

	/**
	 * Parses an OpenPGP packet.
	 *
	 * Partial body lengths based on https://github.com/toofishes/python-pgpdump/blob/master/pgpdump/packet.py
	 *
	 * @see http://tools.ietf.org/html/rfc4880#section-4.2
	 */
	static function parse(&$input)
	{
		if (static::$DEBUG)
			dump(['In METHOD: '=>__METHOD__,'input'=>$input]);

		$packet = NULL;

		if (strlen($input) > 0) {
			$parser = (ord($input[0]) & 64) ? 'parse_new_format' : 'parse_old_format';

			$header_start0 = 0;
			$consumed = 0;
			$packet_data = '';

			do {
				list($tag,$data_offset,$data_length,$partial) = self::$parser($input,$header_start0);

				$data_start0 = $header_start0+$data_offset;
				$header_start0 = $data_start0+$data_length-1;
				$packet_data .= substr($input,$data_start0,$data_length);

				$consumed += $data_offset+$data_length;

				if ($partial) {
					$consumed -= 1;
				}

			} while ($partial === TRUE && $parser === 'parse_new_format');

			if (static::$DEBUG)
				dump(['parser'=>$parser,'tag'=>$tag,'class'=>($class=self::class_for($tag)),'c'=>$class]);

			if ($tag && ($class=self::class_for($tag))) {
				$packet = new $class;
				$packet->tag = $tag;
				$packet->input = $packet_data;
				$packet->length = strlen($packet_data);
				$packet->read();

				unset($packet->input);
				unset($packet->length);
			}

			$input = substr($input,$consumed);
		}

		if (static::$DEBUG)
			dump(['Out METHOD: '=>__METHOD__,'packet'=>$packet]);

		return $packet;
	}

	/**
	 * Parses a new-format (RFC 4880) OpenPGP packet.
	 *
	 * @see http://tools.ietf.org/html/rfc4880#section-4.2.2
	 */
	static function parse_new_format($input,$header_start=0): array
	{
		$tag = ord($input[0]) & 63;
		$len = ord($input[$header_start+1]);

		// One octet length
		if ($len < 192) {
			return [$tag,2,$len,FALSE];
		}

		// Two octet length
		if ($len > 191 && $len < 224) {
			return [$tag,3,(($len-192)<<8)+ord($input[$header_start+2])+192,FALSE];
		}

		// Five octet length
		if ($len == 255) {
			$unpacked = unpack('N',substr($input,$header_start+2,4));

			return [$tag,6,reset($unpacked),FALSE];
		}

		// Partial body lengths
		return [$tag,2,1<<($len & 0x1f),TRUE];
	}

	/**
	 * Parses an old-format (PGP 2.6.x) OpenPGP packet.
	 *
	 * @see http://tools.ietf.org/html/rfc4880#section-4.2.1
	 */
	static function parse_old_format($input): array
	{
		$len = ($tag=ord($input[0]))&3;
		$tag = ($tag>>2)&15;

		switch ($len) {
			// The packet has a one-octet length. The header is 2 octets long.
			case 0:
				$head_length = 2;
				$data_length = ord($input[1]);
				break;

			// The packet has a two-octet length. The header is 3 octets long.
			case 1:
				$head_length = 3;
				$data_length = unpack('n', substr($input, 1, 2));
				$data_length = $data_length[1];
				break;

			// The packet has a four-octet length. The header is 5 octets long.
			case 2:
				$head_length = 5;
				$data_length = unpack('N', substr($input, 1, 4));
				$data_length = $data_length[1];
				break;

			// The packet is of indeterminate length. The header is 1 octet long.
			case 3:
				$head_length = 1;
				$data_length = strlen($input) - $head_length;
				break;
		}

		return [$tag, $head_length, $data_length, FALSE];
	}

	public function __construct($data=NULL)
	{
		// Make sure our tag is set in our packet class.
		try {
			if (is_null($this->tag))
				throw new PacketTagException('Missing tag in '.get_class($this));
		} catch (\Exception $e) {
			dd($e->getMessage());
		}

		if (static::$DEBUG)
			dump(['CREATE: '=>get_class($this),'data'=>$data]);

		if (static::$DEBUG)
			dump([
				'substr1'=>substr(get_class($this),strlen("Leenooks\OpenPGP")+1),
				'substr2'=>substr(substr(get_class($this),strlen("Leenooks\OpenPGP")+1),0,-6),
				'tags: '=>serialize(self::$tags)]);

		$this->tag = array_search(substr(substr(get_class($this),strlen("Leenooks\OpenPGP")+1),0,-6),self::$tags);
		$this->data = $data;
	}

	// Will normally be overridden by subclasses
	public function body()
	{
		return $this->data;
	}

	public function read()
	{
	}

	function header_and_body(): array
	{
		$body = $this->body();									// Get body first, we will need it's length
		$size = chr(255).pack('N',strlen($body));	// Use 5-octet lengths
		$tag = chr($this->tag|0xC0);						// First two bits are 1 for new packet format

		return ['header'=>$tag.$size,'body'=>$body];
	}

	function to_bytes()
	{
		$data = $this->header_and_body();

		return $data['header'].$data['body'];
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-3.5
	 */
	function read_timestamp()
	{
		return $this->read_unpacked(4,'N');
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-3.2
	 */
	function read_mpi()
	{
		$length = $this->read_unpacked(2,'n');	// length in bits
		$length = (int)floor(($length+7)/8);				// length in bytes

		return $this->read_bytes($length);
	}

	/**
	 * @see http://php.net/manual/en/function.unpack.php
	 */
	protected function read_unpacked($count,$format)
	{
		$unpacked = unpack($format,$this->read_bytes($count));

		return reset($unpacked);
	}

	protected function read_byte()
	{
		return ($bytes=$this->read_bytes()) ? $bytes[0] : NULL;
	}

	protected function read_bytes($count=1)
	{
		$bytes = substr($this->input,0,$count);
		$this->input = substr($this->input,$count);

		return $bytes;
	}
}