<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.6
 */
class SignatureExpirationTimePacket extends Subpacket
{
	protected $tag = 3;

	function body()
	{
		return pack('N', $this->data);
	}

	function read()
	{
		$this->data = $this->read_timestamp();
	}
}