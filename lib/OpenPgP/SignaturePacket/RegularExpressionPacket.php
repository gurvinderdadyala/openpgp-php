<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.14
 */
class RegularExpressionPacket extends Subpacket
{
	protected $tag = 6;

	function body()
	{
		return $this->data . chr(0);
	}

	function read()
	{
		$this->data = substr($this->input, 0, -1);
	}
}