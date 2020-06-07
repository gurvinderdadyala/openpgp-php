<?php

namespace Leenooks\OpenPGP;

/**
 * OpenPGP One-Pass Signature packet (tag 4).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.4
 */
class OnePassSignaturePacket extends Packet
{
	protected $tag = 4;
	public $version, $signature_type, $hash_algorithm, $key_algorithm, $key_id, $nested;

	function body()
	{
		$body = chr($this->version).chr($this->signature_type).chr($this->hash_algorithm).chr($this->key_algorithm);
		for($i = 0; $i < strlen($this->key_id); $i += 2) {
			$body .= chr(hexdec($this->key_id{$i}.$this->key_id{$i+1}));
		}
		$body .= chr((int)$this->nested);
		return $body;
	}

	function read()
	{
		$this->version = ord($this->read_byte());
		$this->signature_type = ord($this->read_byte());
		$this->hash_algorithm = ord($this->read_byte());
		$this->key_algorithm = ord($this->read_byte());

		// Store KeyID in Hex
		for ($i=0;$i<8;$i++) {
			$this->key_id .= sprintf('%02X',ord($this->read_byte()));
		}

		$this->nested = ord($this->read_byte());
	}
}