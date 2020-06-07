<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.22
 */
class SignersUserIDPacket extends Subpacket
{
	protected $tag = 28;

	function body()
	{
		return $this->data;
	}

	function read()
	{
		$this->data = $this->input;
	}
}