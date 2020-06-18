<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.5
 */
class IssuerPacket extends Subpacket
{
	protected $tag = 16;

	function body()
	{
		$bytes = '';
		for($i = 0; $i < strlen($this->data); $i += 2) {
			$bytes .= chr(hexdec($this->data[$i].$this->data[$i+1]));
		}
		return $bytes;
	}

	function read()
	{
		for($i = 0; $i < 8; $i++) { // Store KeyID in Hex
			$this->data .= sprintf('%02X',ord($this->read_byte()));
		}
	}
}