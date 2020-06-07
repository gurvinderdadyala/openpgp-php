<?php

namespace Leenooks\OpenPGP;

/**
 * OpenPGP User Attribute packet (tag 17).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.12
 * @see http://tools.ietf.org/html/rfc4880#section-11.1
 */
class UserAttributePacket extends Packet
{
	// TODO
	protected $tag = 17;
	public $packets;
}