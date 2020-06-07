<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.13
 */
class TrustSignaturePacket extends Subpacket
{
	protected $tag = 5;
	
	function body()
	{
		return chr($this->depth) . chr($this->trust);
	}

	function read()
	{
		$this->depth = ord($this->input{0});
		$this->trust = ord($this->input{1});
	}
}