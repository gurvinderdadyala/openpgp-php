<?php

namespace Leenooks\OpenPGP;

/**
 * OpenPGP Public-Subkey packet (tag 14).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.2
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
 * @see http://tools.ietf.org/html/rfc4880#section-11.1
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class PublicSubkeyPacket extends PublicKeyPacket
{
	// TODO
	protected $tag = 14;
}