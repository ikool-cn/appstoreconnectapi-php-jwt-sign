<?php

/**
 * ECSign For App Store Connect API
 * https://developer.apple.com/documentation/appstoreconnectapi/
 * @author ikool
 * @link https://github.com/ikool-cn/appstoreconnectapi-php-jwt-sign
 */
class ECSign
{
    /**
     * sign
     * @param $payload
     * @param $header
     * @param $key
     * @return string
     * @throws Exception
     */
    public static function sign($payload, $header, $key)
    {
        $segments = [];
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = static::_sign($signing_input, $key);
        $segments[] = static::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * openssl_sign
     * @param $msg
     * @param $key
     * @return string
     * @throws Exception
     */
    private static function _sign($msg, $key)
    {
        $key = openssl_pkey_get_private($key);
        if (!$key) {
            throw new \Exception(openssl_error_string());
        }

        $signature = '';
        $success = openssl_sign($msg, $signature, $key, OPENSSL_ALGO_SHA256);
        if (!$success) {
            throw new \Exception("OpenSSL unable to sign data");
        } else {
            $signature = self::fromDER($signature, 64);
            return $signature;
        }
    }

    /**
     * jsonDecode
     * @param $input
     * @return mixed
     * @throws Exception
     */
    private static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            $max_int_length = strlen((string)PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{' . $max_int_length . ',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new \Exception('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * jsonEncode
     * @param $input
     * @return false|string
     * @throws Exception
     */
    private static function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new \Exception('Null result with non-null input');
        }
        return $json;
    }

    /**
     * urlsafeB64Decode
     * @param $input
     * @return false|string
     */
    private static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * urlsafeB64Encode
     * @param $input
     * @return mixed
     */
    private static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * toDER
     * @param string $signature
     * @param int $partLength
     * @return string
     * @throws Exception
     */
    private static function toDER(string $signature, int $partLength): string
    {
        $signature = \unpack('H*', $signature)[1];
        if (\mb_strlen($signature, '8bit') !== 2 * $partLength) {
            throw new \Exception('Invalid length.');
        }
        $R = \mb_substr($signature, 0, $partLength, '8bit');
        $S = \mb_substr($signature, $partLength, null, '8bit');
        $R = self::preparePositiveInteger($R);
        $Rl = \mb_strlen($R, '8bit') / 2;
        $S = self::preparePositiveInteger($S);
        $Sl = \mb_strlen($S, '8bit') / 2;
        $der = \pack('H*',
            '30' . ($Rl + $Sl + 4 > 128 ? '81' : '') . \dechex($Rl + $Sl + 4)
            . '02' . \dechex($Rl) . $R
            . '02' . \dechex($Sl) . $S
        );
        return $der;
    }

    /**
     * toDER
     * @param string $der
     * @param int $partLength
     * @return string
     */
    private static function fromDER(string $der, int $partLength): string
    {
        $hex = \unpack('H*', $der)[1];
        if ('30' !== \mb_substr($hex, 0, 2, '8bit')) { // SEQUENCE
            throw new \RuntimeException();
        }
        if ('81' === \mb_substr($hex, 2, 2, '8bit')) { // LENGTH > 128
            $hex = \mb_substr($hex, 6, null, '8bit');
        } else {
            $hex = \mb_substr($hex, 4, null, '8bit');
        }
        if ('02' !== \mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Rl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $R = self::retrievePositiveInteger(\mb_substr($hex, 4, $Rl * 2, '8bit'));
        $R = \str_pad($R, $partLength, '0', STR_PAD_LEFT);
        $hex = \mb_substr($hex, 4 + $Rl * 2, null, '8bit');
        if ('02' !== \mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Sl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $S = self::retrievePositiveInteger(\mb_substr($hex, 4, $Sl * 2, '8bit'));
        $S = \str_pad($S, $partLength, '0', STR_PAD_LEFT);
        return \pack('H*', $R . $S);
    }

    /**
     * preparePositiveInteger
     * @param string $data
     * @return string
     */
    private static function preparePositiveInteger(string $data): string
    {
        if (\mb_substr($data, 0, 2, '8bit') > '7f') {
            return '00' . $data;
        }
        while ('00' === \mb_substr($data, 0, 2, '8bit') && \mb_substr($data, 2, 2, '8bit') <= '7f') {
            $data = \mb_substr($data, 2, null, '8bit');
        }
        return $data;
    }

    /**
     * retrievePositiveInteger
     * @param string $data
     * @return string
     */
    private static function retrievePositiveInteger(string $data): string
    {
        while ('00' === \mb_substr($data, 0, 2, '8bit') && \mb_substr($data, 2, 2, '8bit') > '7f') {
            $data = \mb_substr($data, 2, null, '8bit');
        }
        return $data;
    }
}