<?php

namespace UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key;

use \Zend\Mail\Address;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class Uid
{
    /** @var string */
    const UID = 'uid';

    /** @var string */
    const PREG_PATTERN_UID = '~'
        . '(?<type>uid)\:'
        . '(?<trust>[a-z\-])?\:'
        . '(?<unknown1>[^\:]+)?\:'
        . '(?<unknown2>[^\:]+)?\:'
        . '(?<unknown3>[^\:]+)?\:'
        . '(?<create>(?:(?<create_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<create_timestamp>[0-9]+)))?\:'
        . '(?<expiry>(?:(?<expiry_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<expiry_timestamp>[0-9]+)))?\:'
        . '(?<fingerprint>[0-9A-F]{40})?\:'
        . '(?<unknown4>[^\:]+)?\:'
        . '(?<owner>[^\:]+)?\:'
        . '~'
    ;

    /** @var string */
    const PREG_PATTERN_OWNER = '~^'
        . '(?<name>[^\(\<]+)'
        . '(\s\((?<comment>[^\)]+)\))?'
        . '\s'
        . '\<(?<email>.*)\>'
        . '$~'
    ;

    /** @var string */
    protected $_fingerprint;

    /** @var \DateTime */
    protected $_create;

    /** @var \DateTime|null */
    protected $_expiry;

    /** @var \Zend\Mail\Address */
    protected $_owner;

    /**
     *
     * @param string $owner
     * @return \Zend\Mail\Address
     * @throws \Exception
     */
    public static function getAddressFromOwner($owner)
    {
        $matches = [];
        if (!preg_match(self::PREG_PATTERN_OWNER, $owner, $matches)) {
            throw new \Exception('can not parse owner "' . $owner . '"');
        }

        return new Address($matches['email'], $matches['name']);
    }

    /**
     *
     * @param array $match
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyAbstract
     */
    public static function factoryByMatch(array $match)
    {
        $uid = new static();
        $uid->setFingerprint($match['fingerprint']);
        $uid->setOwner(static::getAddressFromOwner($match['owner']));

        if (!empty($match['create_datetime'])) {
            $uid->setCreate(\DateTime::createFromFormat('Y-m-d', $match['create_datetime']));
        } elseif (!empty($match['create_timestamp'])) {
            $uid->setCreate(\DateTime::createFromFormat('U', $match['create_timestamp']));
        }

        if (!empty($match['expiry_datetime'])) {
            $uid->setExpiry(\DateTime::createFromFormat('Y-m-d', $match['expiry_datetime']));
        } elseif (!empty($match['expiry_timestamp'])) {
            $uid->setExpiry(\DateTime::createFromFormat('U', $match['expiry_timestamp']));
        }

        return $uid;
    }

    /**
     *
     */
    private function __construct()
    {
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
     * @return \DateTime|null
     */
    public function getExpiry()
    {
        return $this->_expiry;
    }

    /**
     * @param \DateTime $expiry|null
     */
    protected function setExpiry(\DateTime $expiry = null)
    {
        $this->_expiry = $expiry;
    }

    /**
     * @return \DateTime
     */
    public function getCreate()
    {
        return $this->_create;
    }

    /**
     * @param \DateTime $create
     */
    protected function setCreate(\DateTime $create)
    {
        $this->_create = $create;
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
