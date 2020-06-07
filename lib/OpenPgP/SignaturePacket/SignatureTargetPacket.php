<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.25
 */
class SignatureTargetPacket extends Subpacket
{
	protected $tag = 31;
	public $key_algorithm, $hash_algorithm;

	function body()
	{
		return chr($this->key_algorithm) . chr($this->hash_algorithm) . $this->data;
	}

	function read()
	{
		$this->key_algorithm = ord($this->read_byte());
		$this->hash_algorithm = ord($this->read_byte());
		$this->data = $this->input;
	}
}