<?php

namespace UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key;

use \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyAbstract;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class KeyPrimary extends KeyAbstract
{
    /** @var string */
    const TYPE_PUBLIC = 'pub';

    /** @var string */
    const TYPE_SECRET = 'sec';

    /** @var string */
    const PREG_PATTERN_KEYPRIMARY = '~'
        . '(?<type>(?:pub|sec#?))\:'
        . '(?<trust>[a-z\-])?\:'
        . '(?<size>[0-9]+)\:'
        . '(?<bool>[0-9]+)\:'
        . '(?<id>[A-F0-9]{16})\:'
        . '(?<create>(?:(?<create_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<create_timestamp>[0-9]+)))\:'
        . '(?<expiry>(?:(?<expiry_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<expiry_timestamp>[0-9]+)))?\:'
        . '(?<unknown1>[^\:]+)?\:'
        . '(?<trust2>[a-z\-])?\:'
        . '(?<owner>[^\:]+)?\:'
        . '(?<unknown4>[^\:]+)?\:'
        . '(?<capability>[escaESCA]+)\:'
        . '([^\:]*\:){6}'
        . PHP_EOL
        . 'fpr\:'
        . '([^\:]*\:){8}'
        . '(?<fingerprint>[0-9A-F]{40})\:'
        . '~'
    ;

    /** @var string */
    const PREG_PATTERN_KEYPRIMARY_RAW = '~'
        . '(?<type>(?:pub|sec#?))\:'
        . '(?<trust>[a-z\-])?\:'
        . '(?<size>[0-9]+)\:'
        . '(?<bool>[0-9]+)\:'
        . '(?<id>[A-F0-9]{16})\:'
        . '(?<create>(?:(?<create_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<create_timestamp>[0-9]+)))\:'
        . '(?<expiry>(?:(?<expiry_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<expiry_timestamp>[0-9]+)))?\:'
        . '(?<unknown1>[^\:]+)?\:'
        . '(?<trust2>[a-z\-])?\:'
        . '(?<owner>[^\:]+)?\:'
        . '(?<unknown4>[^\:]+)?\:'
        . '(?<capability>[escaESCA]+)\:'
        . '([^\:]*\:){6}'
        . PHP_EOL
        . 'fpr\:'
        . '([^\:]*\:){8}'
        . '(?<fingerprint>[0-9A-F]{40})\:'
        . '~'
    ;

    /** @var string */
    protected $_fingerprint;

    /** @var \Zend\Mail\Address */
    protected $_owner;

    /**
     *
     * @param array $match
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyPrimary
     */
    public static function factoryByMatch(array $match)
    {
        $primary = parent::factoryByMatch($match);
        $primary->setFingerprint($match['fingerprint']);

        if (!empty($match['owner'])) {
            $primary->setOwner(Uid::getAddressFromOwner($match['owner']));
        }

        return $primary;
    }

    /**
     * @return string
     */
    public function getFingerprint()
    {
        return $this->_fingerprint;
    }

    /**
     * @param string $fingerprint
     */
    protected function setFingerprint($fingerprint)
    {
        $this->_fingerprint = $fingerprint;
    }

    /**
     * @return \Zend\Mail\Address
     */
    public function getOwner()
    {
        return $this->_owner;
    }

    /**
     * @param \Zend\Mail\Address $owner
     */
    protected function setOwner(\Zend\Mail\Address $owner)
    {
        $this->_owner = $owner;
    }
}
