<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.18
 */
class PreferredKeyServerPacket extends Subpacket
{
	protected $tag = 24;

	function body()
	{
		return $this->data;
	}

	function read()
	{
		$this->data = $this->input;
	}
}