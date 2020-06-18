<?php

namespace Leenooks\OpenPGP\SignaturePacket;

use Leenooks\OpenPGP\Exceptions\PacketTagException;
use Leenooks\OpenPGP\Packet;

class Subpacket extends Packet
{
	protected $tag = NULL;

	function body()
	{
		return $this->data;
	}

	function header_and_body(): array
	{
		$body = $this->body();											// Get body first, we will need it's length
		$size = chr(255).pack('N',strlen($body)+1);	// Use 5-octet lengths + 1 for tag as first packet body octet
		$tag = chr($this->tag);

		return ['header'=>$size.$tag,'body'=>$body];
	}

	/* Defaults for unsupported packets */
	function read()
	{
		$this->data = $this->input;
	}

	public function setTag(int $tag): void
	{
		if (get_class($this) !== Subpacket::class)
			throw new PacketTagException('Attempting to set a tag for invalid class: ',get_class($this));

		$this->tag = $tag;
	}
}