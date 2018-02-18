<?php

namespace UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
abstract class KeyAbstract
{
    /** @var string */
    const CAPABILITY_SIGN = 's';
    const CAPABILITY_ENCRYPT = 'e';
    const CAPABILITY_AUTHENTICATE = 'a';
    const CAPABILITY_CERTIFY = 'c';

    /** @var string */
    protected $_id;

    /** @var \DateTime */
    protected $_create;

    /** @var \DateTime|null */
    protected $_expiry;

    /** @var array */
    protected $_capabilities = [];

    /**
     *
     * @param array $match
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyAbstract
     */
    public static function factoryByMatch(array $match)
    {
        $key = new static();
        $key->setId($match['id']);

        if (!empty($match['create_datetime'])) {
            $key->setCreate(\DateTime::createFromFormat('Y-m-d', $match['create_datetime']));
        } elseif (!empty($match['create_timestamp'])) {
            $key->setCreate(\DateTime::createFromFormat('U', $match['create_timestamp']));
        }

        if (!empty($match['expiry_datetime'])) {
            $key->setExpiry(\DateTime::createFromFormat('Y-m-d', $match['expiry_datetime']));
        } elseif (!empty($match['expiry_timestamp'])) {
            $key->setExpiry(\DateTime::createFromFormat('U', $match['expiry_timestamp']));
        }

        //$primary->setCapabilities();

        return $key;
    }

    /**
     *
     */
    protected function __construct()
    {
    }

    /**
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg $gpg
     * @return string
     */
    //abstract public function export(Gpg $gpg);

    /**
     * @return string
     */
    public function getId()
    {
        return $this->_id;
    }

    /**
     * @param string $id
     */
    protected function setId($id)
    {
        $this->_id = $id;
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
     * @return array
     */
    public function getCapabilities()
    {
        return $this->_capabilities;
    }

    /**
     * @param array $capabilities
     */
    protected function setCapabilities(array $capabilities)
    {
        $this->_capabilities = $capabilities;
    }

    /**
     * @param string $capability
     * @return boolean
     */
    public function hasCapability($capability)
    {
        return in_array($capability, $this->_capabilities);
    }
}
