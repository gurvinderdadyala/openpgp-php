<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.17
 */
class KeyServerPreferencesPacket extends Subpacket
{
	protected $tag = 23;
	public $no_modify;

	function body()
	{
		return chr($this->no_modify ? 0x80 : 0x00);
	}

	function read()
	{
		$flags = ord($this->input);
		$this->no_modify = $flags & 0x80 == 0x80;
	}
}