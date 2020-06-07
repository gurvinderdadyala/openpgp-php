<?php

namespace Leenooks\OpenPGP\SignaturePacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.24
 * @note Identical functionality to parent
 */
class FeaturesPacket extends KeyFlagsPacket
{
	protected $tag = 30;
}