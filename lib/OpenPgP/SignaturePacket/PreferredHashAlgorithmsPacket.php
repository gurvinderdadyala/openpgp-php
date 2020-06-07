<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.8
 */
class PreferredHashAlgorithmsPacket extends Subpacket
{
	protected $tag = 21;
	
	function body()
	{
		$bytes = '';
		foreach($this->data as $algo) {
			$bytes .= chr($algo);
		}
		return $bytes;
	}

	function read()
	{
		$this->data = array();

		while(strlen($this->input) > 0) {
			$this->data[] = ord($this->read_byte());
		}
	}
}