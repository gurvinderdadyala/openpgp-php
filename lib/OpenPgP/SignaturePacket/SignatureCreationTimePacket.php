<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.4
 */
class SignatureCreationTimePacket extends Subpacket
{
	protected $tag = 2;

	function body()
	{
		return pack('N',$this->data);
	}

	function read()
	{
		$this->data = $this->read_timestamp();
	}
}