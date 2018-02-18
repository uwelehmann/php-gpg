<?php

namespace UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key;

use \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyAbstract;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class KeySub extends KeyAbstract
{
    /** @var string */
    const TYPE_PUBLIC = 'sub';

    /** @var string */
    const TYPE_SECRET = 'ssb';

    /** @var string */
    const PREG_PATTERN_KEYSUB = '~'
        . '(?<type>(?:sub|ssb))\:'
        . '(?<trust>[a-z\-])?\:'
        . '(?<size>[0-9]+)\:'
        . '(?<bool>[0-9]+)\:'
        . '(?<id>[A-F0-9]{16})\:'
        . '(?<create>(?:(?<create_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<create_timestamp>[0-9]+)))\:'
        . '(?<expiry>(?:(?<expiry_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<expiry_timestamp>[0-9]+)))?\:'
        . '(?<unknown1>[^\:]+)?\:'
        . '(?<unknown2>[^\:]+)?\:'
        . '(?<unknown3>[^\:]+)?\:'
        . '(?<unknown4>[^\:]+)?\:'
        . '(?<capability>[escaESCA]+)\:'
        . '(([^\:]*\:){5})?'
        . '~'
    ;

    /** @var string */
    const PREG_PATTERN_KEYSUB_RAW = '~'
        . '(?<type>(?:sub|ssb))\:'
        . '(?<trust>[a-z\-])?\:'
        . '(?<size>[0-9]+)\:'
        . '(?<bool>[0-9]+)\:'
        . '(?<id>[A-F0-9]{16})\:'
        . '(?<create>(?:(?<create_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<create_timestamp>[0-9]+)))\:'
        . '(?<expiry>(?:(?<expiry_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<expiry_timestamp>[0-9]+)))?\:'
        . '(?<unknown1>[^\:]+)?\:'
        . '(?<unknown2>[^\:]+)?\:'
        . '(?<unknown3>[^\:]+)?\:'
        . '(?<unknown4>[^\:]+)?\:'
        . '(?<capability>[escaESCA]+)\:'
        . '(([^\:]*\:){5})?'
        . '~'
    ;

    /**
     *
     * @param array $match
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeySub
     */
    public static function factoryByMatch(array $match)
    {
        return parent::factoryByMatch($match);
    }
}
