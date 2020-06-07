<?php

namespace Leenooks\OpenPGP;

/**
 * OpenPGP Trust packet (tag 12).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.10
 */
class TrustPacket extends Packet
{
	protected $tag = 12;

	function read() {
		$this->data = $this->input;
	}
}