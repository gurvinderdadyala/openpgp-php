<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.20
 */
class PolicyURIPacket extends Subpacket
{
	protected $tag = 26;

	function body()
	{
		return $this->data;
	}

	function read()
	{
		$this->data = $this->input;
	}
}