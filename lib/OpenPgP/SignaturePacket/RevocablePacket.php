<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.15
 */
class RevocablePacket extends Subpacket
{
	protected $tag = 7;

	function body()
	{
		return chr($this->data ? 1 : 0);
	}

	function read()
	{
		$this->data = (ord($this->input) != 0);
	}
}