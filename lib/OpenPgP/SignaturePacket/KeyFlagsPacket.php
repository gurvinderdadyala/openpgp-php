<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.21
 */
class KeyFlagsPacket extends Subpacket
{
	protected $tag = 27;

	function __construct($flags=[])
	{
		parent::__construct();

		$this->flags = $flags;
	}

	function body()
	{
		$bytes = '';

		foreach($this->flags as $f) {
			$bytes .= chr($f);
		}
		return $bytes;
	}

	function read()
	{
		$this->flags = array();

		while($this->input) {
			$this->flags[] = ord($this->read_byte());
		}
	}
}