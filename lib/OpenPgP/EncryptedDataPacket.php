<?php

namespace Leenooks\OpenPGP;

/**
 * OpenPGP Symmetrically Encrypted Data packet (tag 9).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.7
 */
class EncryptedDataPacket extends Packet
{
	protected $tag = 9;

	function read()
	{
		$this->data = $this->input;
	}
}