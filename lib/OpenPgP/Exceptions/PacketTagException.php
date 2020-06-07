<?php

namespace Leenooks\OpenPGP\Exceptions;

class PacketTagException extends \Exception
{
	protected $message = 'Packet class missing tag value';

	public function __construct($message, $code = 0, Exception $previous = null)
	{
		if ($message)
			$this->message = $message;
	}
}