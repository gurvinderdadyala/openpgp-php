<?php

namespace Leenooks\OpenPGP;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-11
 * @see http://tools.ietf.org/html/rfc4880#section-11.3
 */
class Message implements \IteratorAggregate,\ArrayAccess
{
	protected $packets;
	protected $uri = NULL;

	// IteratorAggregate interface

	function getIterator()
	{
		return new \ArrayIterator($this->packets);
	}

	// ArrayAccess interface

	function offsetExists($offset)
	{
		return isset($this->packets[$offset]);
	}

	function offsetGet($offset)
	{
		return $this->packets[$offset];
	}

	function offsetSet($offset,$value)
	{
		return is_null($offset) ? $this->packets[] = $value : $this->packets[$offset] = $value;
	}

	function offsetUnset($offset)
	{
		unset($this->packets[$offset]);
	}

	// Class

	function __construct(array $packets=[])
	{
		$this->packets = $packets;
	}

	/**
	 * @see http://tools.ietf.org/html/rfc4880#section-4.1
	 * @see http://tools.ietf.org/html/rfc4880#section-4.2
	 */
	static function parse($input): self
	{
		if (is_resource($input)) {
			return self::parse_stream($input);
		}

		if (is_string($input)) {
			return self::parse_string($input);
		}
	}

	static function parse_file($path): self
	{
		if (($msg=self::parse(file_get_contents($path)))) {
			$msg->uri = preg_match('!^[\w\d]+://!',$path) ? $path : 'file://'.realpath($path);

			return $msg;
		}
	}

	static function parse_stream($input): self
	{
		return self::parse_string(stream_get_contents($input));
	}

	static function parse_string($input): self
	{
		$msg = new self;

		while (($length=strlen($input)) > 0) {
			if (($packet=Packet::parse($input))) {
				$msg[] = $packet;
			}

			// is parsing stuck?
			if ($length == strlen($input)) {
				break;
			}
		}

		return $msg;
	}

	/**
	 * Extract signed objects from a well-formatted message
	 *
	 * Recurses into CompressedDataPacket
	 *
	 * @see http://tools.ietf.org/html/rfc4880#section-11
	 */
	public function signatures(): array
	{
		$msg = $this;

		$key = NULL;
		$userid = NULL;
		$subkey = NULL;
		$sigs = [];
		$final_sigs = [];

		while ($msg[0] instanceof CompressedDataPacket)
			$msg = $msg[0]->data;

		foreach ($msg as $idx => $p) {
			if ($p instanceof LiteralDataPacket) {
				return [
					[
						$p,
						array_values(array_filter($msg->packets,function($p)
						{
							return $p instanceof SignaturePacket;
						}))
					]
				];

			} elseif ($p instanceof PublicSubkeyPacket || $p instanceof SecretSubkeyPacket) {
				if ($userid) {
					array_push($final_sigs,[$key,$userid,$sigs]);
					$userid = NULL;

				} elseif ($subkey) {
					array_push($final_sigs,[$key,$subkey,$sigs]);
					$key = NULL;
				}

				$sigs = [];
				$subkey = $p;

			} elseif ($p instanceof PublicKeyPacket) {
				if ($userid) {
					array_push($final_sigs,[$key,$userid,$sigs]);
					$userid = NULL;

				} elseif ($subkey) {
					array_push($final_sigs,[$key,$subkey,$sigs]);
					$subkey = NULL;

				} elseif ($key) {
					array_push($final_sigs,[$key,$sigs]);
					$key = NULL;
				}

				$sigs = [];
				$key = $p;

			} elseif ($p instanceof UserIDPacket) {
				if ($userid) {
					array_push($final_sigs,[$key,$userid,$sigs]);
					$userid = NULL;

				} elseif ($key) {
					array_push($final_sigs,[$key,$sigs]);
				}

				$sigs = [];
				$userid = $p;

			} elseif ($p instanceof SignaturePacket) {
				$sigs[] = $p;
			}
		}

		if ($userid) {
			array_push($final_sigs,[$key,$userid,$sigs]);

		} elseif ($subkey) {
			array_push($final_sigs,[$key,$subkey,$sigs]);

		} elseif ($key) {
			array_push($final_sigs,[$key,$sigs]);
		}

		return $final_sigs;
	}

	public function to_bytes(): string
	{
		$bytes = '';

		foreach ($this as $p) {
			$bytes .= $p->to_bytes();
		}

		return $bytes;
	}

	/**
	 * Function to extract verified signatures
	 *
	 * $verifiers is an array of callbacks formatted like array('RSA' => array('SHA256' => CALLBACK)) that take two parameters: raw message and signature packet
	 */
	function verified_signatures($verifiers): array
	{
		$signed = $this->signatures();
		$vsigned = [];

		foreach ($signed as $sign) {
			$signatures = array_pop($sign);
			$vsigs = [];

			foreach ($signatures as $sig) {
				$verifier = $verifiers[$sig->key_algorithm_name()][$sig->hash_algorithm_name()];

				if ($verifier && $this->verify_one($verifier,$sign,$sig)) {
					$vsigs[] = $sig;
				}
			}

			array_push($sign,$vsigs);
			$vsigned[] = $sign;
		}

		return $vsigned;
	}

	function verify_one($verifier,$sign,$sig)
	{
		if ($sign[0] instanceof LiteralDataPacket) {
			$sign[0]->normalize();
			$raw = $sign[0]->data;

		} elseif (isset($sign[1]) && $sign[1] instanceof UserIDPacket) {
			$raw = implode(
				'',
				array_merge(
					$sign[0]->fingerprint_material(),
					array(chr(0xB4),pack('N',strlen($sign[1]->body())),$sign[1]->body())
				));

		} elseif (isset($sign[1]) && ($sign[1] instanceof PublicSubkeyPacket || $sign[1] instanceof SecretSubkeyPacket)) {
			$raw = implode('',array_merge($sign[0]->fingerprint_material(),$sign[1]->fingerprint_material()));

		} elseif ($sign[0] instanceof PublicKeyPacket) {
			$raw = implode('',$sign[0]->fingerprint_material());

		} else {
			return NULL;
		}

		return call_user_func($verifier,$raw.$sig->trailer,$sig);
	}
}