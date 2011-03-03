<?php defined('SYSPATH') or die('No direct script access.');
/**
 * The following class generates valid [RFC 4211][ref-rfc-4211] compliant
 * Universally Unique IDentifiers (UUID) version 3, 4 and 5. UUIDs generated
 * validate using OSSP UUID Tool, and output for named-based UUIDs are exactly
 * the same. This is a pure PHP implementation.
 *
 * Adapted from code published by [Andrew Moore][ref-php-94959].
 *
 * [ref-rfc-4211]: http://www.ietf.org/rfc/rfc4211.txt
 * [ref-php-94959]: http://www.php.net/manual/en/function.uniqid.php#94959
 *
 * @package    Kohana
 * @category   Security
 * @author     Andrew Moore
 * @author     Kohana Team
 * @copyright  (c) 2011 Kohana Team
 * @license    http://kohanaframework.org/license
 */
class Kohana_UUID {

	/**
	 * @var  string  NULL UUID string
	 */
	const NULL = '00000000-0000-0000-0000-000000000000';

	/**
	 * Checks if a UUID has a valid format.
	 *
	 * @param   string  UUID
	 * @return  boolean
	 */
	public static function valid($uuid)
	{
		return (preg_match('/^\{?[0-9a-f]{8}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{12}\}?$/i', $uuid) === 1);
	}

	/**
	 * Version 3 UUIDs are named based. They require a namespace (another
	 * valid UUID) and a value (the name). Given the same namespace and
	 * name, the output is always the same.
	 *
	 * @param   string  namespace
	 * @param   string  key name
	 * @return  string
	 */
	public static function v3($namespace, $name)
	{
		if ( ! UUID::valid($namespace))
		{
			// All namespaces must be valid UUIDs
			return FALSE;
		}

		// Get hexadecimal components of namespace
		$nhex = str_replace(array('-','{','}'), '', $namespace);

		// Binary Value
		$nstr = '';

		// Convert Namespace UUID to bits
		for ($i = 0, $max = strlen($nhex); $i < $max; $i += 2)
		{
			$nstr .= chr(hexdec($nhex[$i].$nhex[$i + 1]));
		}

		// Calculate hash value
		$hash = md5($nstr.$name);

		return sprintf('%08s-%04s-%04x-%04x-%12s',
			// 32 bits for "time_low"
			substr($hash, 0, 8),

			// 16 bits for "time_mid"
			substr($hash, 8, 4),

			// 16 bits for "time_hi_and_version",
			// four most significant bits holds version number 3
			(hexdec(substr($hash, 12, 4)) & 0x0fff) | 0x3000,

			// 16 bits, 8 bits for "clk_seq_hi_res",
			// 8 bits for "clk_seq_low",
			// two most significant bits holds zero and one for variant DCE1.1
			(hexdec(substr($hash, 16, 4)) & 0x3fff) | 0x8000,

			// 48 bits for "node"
			substr($hash, 20, 12)
		);
	}

	/**
	 * Version 4 UUIDs are pseudo-random.
	 *
	 * @return  string
	 */
	public static function v4()
	{
		return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			// 32 bits for "time_low"
			mt_rand(0, 0xffff), mt_rand(0, 0xffff),

			// 16 bits for "time_mid"
			mt_rand(0, 0xffff),

			// 16 bits for "time_hi_and_version",
			// four most significant bits holds version number 4
			mt_rand(0, 0x0fff) | 0x4000,

			// 16 bits, 8 bits for "clk_seq_hi_res",
			// 8 bits for "clk_seq_low",
			// two most significant bits holds zero and one for variant DCE1.1
			mt_rand(0, 0x3fff) | 0x8000,

			// 48 bits for "node"
			mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
		);
	}

	/**
	 * Version 5 UUIDs are named based. They require a namespace (another
	 * valid UUID) and a value (the name). Given the same namespace and
	 * name, the output is always the same.
	 *
	 * @param   string   namespace
	 * @param   string   key name
	 * @return  string
	 */
	public static function v5($namespace, $name)
	{
		if ( ! UUID::valid($namespace))
		{
			// All namespaces must be valid UUIDs
			return FALSE;
		}

		// Get hexadecimal components of namespace
		$nhex = str_replace(array('-','{','}'), '', $namespace);

		// Binary Value
		$nstr = '';

		// Convert Namespace UUID to bits
		for ($i = 0, $max = strlen($nhex); $i < $max; $i += 2)
		{
			$nstr .= chr(hexdec($nhex[$i].$nhex[$i + 1]));
		}

		// Calculate hash value
		$hash = sha1($nstr.$name);

		return sprintf('%08s-%04s-%04x-%04x-%12s',
			// 32 bits for "time_low"
			substr($hash, 0, 8),

			// 16 bits for "time_mid"
			substr($hash, 8, 4),

			// 16 bits for "time_hi_and_version",
			// four most significant bits holds version number 5
			(hexdec(substr($hash, 12, 4)) & 0x0fff) | 0x5000,

			// 16 bits, 8 bits for "clk_seq_hi_res",
			// 8 bits for "clk_seq_low",
			// two most significant bits holds zero and one for variant DCE1.1
			(hexdec(substr($hash, 16, 4)) & 0x3fff) | 0x8000,

			// 48 bits for "node"
			substr($hash, 20, 12)
		);
	}

} // End UUID
