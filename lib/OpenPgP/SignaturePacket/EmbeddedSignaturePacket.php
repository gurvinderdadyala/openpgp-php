<?php

namespace Leenooks\OpenPGP\SignaturePacket;

use Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.26
 */
class EmbeddedSignaturePacket extends SignaturePacket
{
	protected $tag = 32;

	function header_and_body(): array
	{
		$body = $this->body();												// Get body first, we will need it's length
		$size = chr(255).pack('N',strlen($body)+1);		// Use 5-octet lengths + 1 for tag as first packet body octet
		$tag = chr($this->tag);

		return ['header'=>$size.$tag,'body'=>$body];
	}
}