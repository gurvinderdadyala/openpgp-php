<?php

namespace Leenooks\OpenPGP;

use Leenooks\OpenPGP;

/**
 * OpenPGP Signature packet (tag 2).
 * Be sure to NULL the trailer if you update a signature packet!
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.2
 */
class SignaturePacket extends Packet
{
	protected $tag = 2;
	public $version, $signature_type, $hash_algorithm, $key_algorithm, $hashed_subpackets, $unhashed_subpackets, $hash_head;

	// This is the literal bytes that get tacked on the end of the message when verifying the signature
	public $trailer;

	static $hash_algorithms = [
		1 => 'MD5',
		2 => 'SHA1',
		3 => 'RIPEMD160',
		8 => 'SHA256',
		9 => 'SHA384',
		10 => 'SHA512',
		11 => 'SHA224'
	];

	static $subpacket_types = [
		//0 => 'Reserved',
		//1 => 'Reserved',
		2 => 'SignatureCreationTime',
		3 => 'SignatureExpirationTime',
		4 => 'ExportableCertification',
		5 => 'TrustSignature',
		6 => 'RegularExpression',
		7 => 'Revocable',
		//8 => 'Reserved',
		9 => 'KeyExpirationTime',
		//10 => 'Placeholder for backward compatibility',
		11 => 'PreferredSymmetricAlgorithms',
		12 => 'RevocationKey',
		//13 => 'Reserved',
		//14 => 'Reserved',
		//15 => 'Reserved',
		16 => 'Issuer',
		//17 => 'Reserved',
		//18 => 'Reserved',
		//19 => 'Reserved',
		20 => 'NotationData',
		21 => 'PreferredHashAlgorithms',
		22 => 'PreferredCompressionAlgorithms',
		23 => 'KeyServerPreferences',
		24 => 'PreferredKeyServer',
		25 => 'PrimaryUserID',
		26 => 'PolicyURI',
		27 => 'KeyFlags',
		28 => 'SignersUserID',
		29 => 'ReasonforRevocation',
		30 => 'Features',
		31 => 'SignatureTarget',
		32 => 'EmbeddedSignature',
	];

	function __construct($data=NULL,$key_algorithm=NULL,$hash_algorithm=NULL)
	{
		parent::__construct();

		// Default to version 4 sigs
		$this->version = 4;

		if (is_string($this->hash_algorithm = $hash_algorithm)) {
			$this->hash_algorithm = array_search($this->hash_algorithm, self::$hash_algorithms);
		}

		if (is_string($this->key_algorithm = $key_algorithm)) {
			$this->key_algorithm = array_search($this->key_algorithm,PublicKeyPacket::$algorithms);
		}

		// If we have any data, set up the creation time
		if ($data) {
			$this->hashed_subpackets = [new SignaturePacket\SignatureCreationTimePacket(time())];
		}

		if ($data instanceof LiteralDataPacket) {
			$this->signature_type = ($data->format == 'b') ? 0x00 : 0x01;
			$data->normalize();
			$data = $data->data;

		} elseif ($data instanceof Message && $data[0] instanceof PublicKeyPacket) {
			// $data is a message with PublicKey first, UserID second
			$key = implode('',$data[0]->fingerprint_material());
			$user_id = $data[1]->body();
			$data = $key.chr(0xB4).pack('N',strlen($user_id)).$user_id;
		}

		// Store to-be-signed data in here until the signing happens
		$this->data = $data;
	}

	function body()
	{
		switch($this->version) {
			case 2:
			case 3:
				$body = chr($this->version).chr(5).chr($this->signature_type);

				foreach ((array)$this->unhashed_subpackets as $p) {
					if ($p instanceof SignaturePacket\SignatureCreationTimePacket) {
						$body .= pack('N',$p->data);

						break;
					}
				}

				foreach ((array)$this->unhashed_subpackets as $p) {
					if ($p instanceof SignaturePacket\IssuerPacket) {
						for($i = 0; $i < strlen($p->data); $i += 2) {
							$body .= chr(hexdec($p->data[$i].$p->data[$i+1]));
						}

						break;
					}
				}

				$body .= chr($this->key_algorithm);
				$body .= chr($this->hash_algorithm);
				$body .= pack('n',$this->hash_head);

				foreach ($this->data as $mpi) {
					$body .= pack('n',OpenPGP::bitlength($mpi)).$mpi;
				}

				return $body;

			case 4:
				if (!$this->trailer)
					$this->trailer = $this->calculate_trailer();

				$body = substr($this->trailer,0,-6);

				$unhashed_subpackets = '';
				foreach((array)$this->unhashed_subpackets as $p) {
					$unhashed_subpackets .= $p->to_bytes();
				}

				$body .= pack('n',strlen($unhashed_subpackets)).$unhashed_subpackets;

				$body .= pack('n',$this->hash_head);

				foreach ((array)$this->data as $mpi) {
					$body .= pack('n',OpenPGP::bitlength($mpi)).$mpi;
				}

				return $body;
		}
	}

	function body_start()
	{
		$body = chr(4).chr($this->signature_type).chr($this->key_algorithm).chr($this->hash_algorithm);

		$hashed_subpackets = '';
		foreach((array)$this->hashed_subpackets as $p) {
			$hashed_subpackets .= $p->to_bytes();
		}

		$body .= pack('n',strlen($hashed_subpackets)).$hashed_subpackets;

		return $body;
	}

	function calculate_trailer() {
		// The trailer is just the top of the body plus some crap
		$body = $this->body_start();

		return $body.chr(4).chr(0xff).pack('N',strlen($body));
	}

	static function class_for($tag)
	{
		return (isset(self::$subpacket_types[$tag]) AND class_exists($class='Leenooks\OpenPGP\SignaturePacket\\'.self::$subpacket_types[$tag].'Packet'))
			? $class
			: 'Leenooks\OpenPGP\SignaturePacket\Subpacket';
	}

	static function get_subpacket(&$input)
	{
		if (self::$DEBUG)
			dump(['method'=>__METHOD__,'input'=>$input]);

		$len = ord($input[0]);
		$length_of_length = 1;

		if (self::$DEBUG)
			dump(['len'=>$len]);

		// if($len < 192) One octet length, no furthur processing
		if ($len > 190 && $len < 255) { // Two octet length
			$length_of_length = 2;
			$len = (($len - 192) << 8) + ord($input[1]) + 192;
		}

		// Five octet length
		if ($len == 255) {
			$length_of_length = 5;
			$unpacked = unpack('N', substr($input, 1, 4));
			$len = reset($unpacked);
			if (self::$DEBUG)
				dump(['len'=>$len,'unpacked'=>$unpacked]);
		}

		$input = substr($input,$length_of_length); // Chop off length header
		$tag = ord($input[0]);

		$class = self::class_for($tag);

		if (self::$DEBUG)
			dump(['class'=>$class,'tag'=>$tag]);

		if ($class) {
			$packet = new $class;

			// In case we got the catch all class.
			if ($class == 'Leenooks\OpenPGP\SignaturePacket\Subpacket')
				$packet->setTag($tag);

			if ($packet->tag() !== $tag)
				throw new OpenPGP\Exceptions\PacketTagException(sprintf('Packet tag [%s] doesnt match tag [%s]?',$packet->tag(),$tag));
			//$packet->tag = $tag;				// @todo Tag should already be set.
			$packet->input = substr($input, 1, $len-1);
			$packet->length = $len-1;
			$packet->read();
			unset($packet->input);
			unset($packet->length);
		}

		// Chop off the data from this packet
		$input = substr($input,$len);

		return $packet;
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.1
	 */
	static function get_subpackets($input)
	{
		$subpackets = array();

		while(($length = strlen($input)) > 0) {
			$subpackets[] = self::get_subpacket($input);

			// Parsing stuck?
			if ($length == strlen($input)) {
				break;
			}
		}

		return $subpackets;
	}

	function hash_algorithm_name()
	{
		return self::$hash_algorithms[$this->hash_algorithm];
	}

	function issuer()
	{
		foreach ($this->hashed_subpackets as $p) {
			if ($p instanceof SignaturePacket\IssuerPacket)
				return $p->data;
		}

		foreach($this->unhashed_subpackets as $p) {
			if ($p instanceof SignaturePacket\IssuerPacket)
				return $p->data;
		}

		return NULL;
	}

	function key_algorithm_name()
	{
		return PublicKeyPacket::$algorithms[$this->key_algorithm];
	}

	function read()
	{
		switch($this->version = ord($this->read_byte())) {
			case 2:
			case 3:
				if (ord($this->read_byte()) != 5) {
					throw new Exception("Invalid version 2 or 3 SignaturePacket");
				}

				$this->signature_type = ord($this->read_byte());
				$creation_time = $this->read_timestamp();
				$keyid = $this->read_bytes(8);
				$keyidHex = '';

				// Store KeyID in Hex
				for ($i=0;$i<strlen($keyid);$i++) {
					$keyidHex .= sprintf('%02X',ord($keyid[$i]));
				}

				$this->hashed_subpackets = [];
				$this->unhashed_subpackets = [
					new SignaturePacket\SignatureCreationTimePacket($creation_time),
					new SignaturePacket\IssuerPacket($keyidHex)
				];

				$this->key_algorithm = ord($this->read_byte());
				$this->hash_algorithm = ord($this->read_byte());
				$this->hash_head = $this->read_unpacked(2, 'n');
				$this->data = array();

				while (strlen($this->input)>0) {
					$this->data[] = $this->read_mpi();
				}

				break;

			case 4:
				$this->signature_type = ord($this->read_byte());
				$this->key_algorithm = ord($this->read_byte());
				$this->hash_algorithm = ord($this->read_byte());
				$this->trailer = chr(4).chr($this->signature_type).chr($this->key_algorithm).chr($this->hash_algorithm);

				$hashed_size = $this->read_unpacked(2, 'n');
				$hashed_subpackets = $this->read_bytes($hashed_size);
				$this->trailer .= pack('n', $hashed_size).$hashed_subpackets;
				$this->hashed_subpackets = self::get_subpackets($hashed_subpackets);

				$this->trailer .= chr(4).chr(0xff).pack('N', 6 + $hashed_size);

				$unhashed_size = $this->read_unpacked(2, 'n');
				$this->unhashed_subpackets = self::get_subpackets($this->read_bytes($unhashed_size));

				$this->hash_head = $this->read_unpacked(2, 'n');

				$this->data = array();

				while(strlen($this->input) > 0) {
					$this->data[] = $this->read_mpi();
				}

				break;
		}
	}

	/**
	 * $this->data must be set to the data to sign (done by constructor)
	 * $signers in the same format as $verifiers for Message.
	 */
	public function sign_data($signers)
	{
		$this->trailer = $this->calculate_trailer();
		$signer = $signers[$this->key_algorithm_name()][$this->hash_algorithm_name()];
		$this->data = call_user_func($signer,$this->data.$this->trailer);
		$unpacked = unpack('n', substr(implode('',$this->data),0,2));
		$this->hash_head = reset($unpacked);
	}
}