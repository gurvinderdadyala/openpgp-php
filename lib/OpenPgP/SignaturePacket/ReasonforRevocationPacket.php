<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.23
 */
class ReasonforRevocationPacket extends Subpacket
{
	protected $tag = 29;
	public $code;

	function body()
	{
		return chr($this->code) . $this->data;
	}

	function read()
	{
		$this->code = ord($this->read_byte());
		$this->data = $this->input;
	}
}