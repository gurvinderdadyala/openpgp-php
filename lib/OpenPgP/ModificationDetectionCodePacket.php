<?php

namespace Leenooks\OpenPGP;

/**
 * OpenPGP Modification Detection Code packet (tag 19).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.14
 */
class ModificationDetectionCodePacket extends Packet
{
	protected $tag = 19;

	function header_and_body(): array
	{
		// Get body first, we will need it's length
		$body = $this->body();

		if (strlen($body) != 20)
			throw new Exception("Bad ModificationDetectionCodePacket");

		return ['header'=>"\xD3\x14",'body'=>$body];
	}

	function read()
	{
		$this->data = $this->input;

		if (strlen($this->input) != 20)
			throw new Exception("Bad ModificationDetectionCodePacket");
	}
}