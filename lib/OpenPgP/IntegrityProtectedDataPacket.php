<?php

namespace Leenooks\OpenPGP;

/**
 * OpenPGP Sym. Encrypted Integrity Protected Data packet (tag 18).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.13
 */
class IntegrityProtectedDataPacket extends EncryptedDataPacket
{
	protected $tag = 18;
	public $version;

	function __construct($data='',$version=1) {
		parent::__construct($data);

		$this->version = $version;
	}

	function body()
	{
		return chr($this->version).$this->data;
	}

	function read()
	{
		$this->version = ord($this->read_byte());
		$this->data = $this->input;
	}
}