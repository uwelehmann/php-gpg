<?php

namespace UweLehmann\Gpg\Crypt\PublicKey\Gpg;

use UweLehmann\Gpg\Crypt\PublicKey\Gpg;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyPrimary;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeySub;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\Uid;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class KeyRaw
{
    /** @var string */
    const TYPE_PUBLIC = 'pub';

    /** @var string */
    const TYPE_SECRET = 'sec';

    /** @var string */
    const PREG_PATTERN_FROM_RAW = '~'
        . '(?<type>(sec|pub))\:'
        . '(?<trust>[a-z\-])?\:'
        . '(?<size>[0-9]+)\:'
        . '(?<bool>[0-9]+)\:'
        . '(?<id>[A-F0-9]{16})\:'
        . '(?<create>(?:(?<create_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<create_timestamp>[0-9]+)))\:'
        . '(?<expiry>(?:(?<expiry_datetime>[0-9]{4}\-[0-9]{2}\-[0-9]{2})|(?<expiry_timestamp>[0-9]+)))?\:'
        . '(?<unknown1>[^\:]+)?\:'
        . '(?<trust2>[a-z\-])?\:'
        . PHP_EOL
        . 'fpr\:'
        . '\:{8}'
        . '(?<fingerprint>[0-9A-F]{40})\:'
        . '~'
    ;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpg;

    /** @var string */
    protected $_raw;

    /** @var string */
    protected $_type;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyPrimary */
    protected $_primary;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeySub[] */
    protected $_sub = [];

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\Uid[] */
    protected $_uid = [];

    /**
     *
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg $gpg
     * @param string $raw
     * @param string $password
     * @throws \Exception
     */
    public function __construct(Gpg $gpg, $raw, $password = null)
    {
        $this->_gpg = $gpg;
        $this->_raw = $raw;

        $this->_parseKeyByRaw($raw, $password);
    }

    /**
     *
     * @return string
     */
    public function __toString()
    {
        return "{$this->getRaw()}";
    }

    /**
     *
     * @return string
     */
    public function getRaw()
    {
        return $this->_raw;
    }

    /**
     *
     * @return string
     */
    public function getType()
    {
        return $this->_type;
    }

    /**
     *
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyPrimary
     */
    public function getPrimary()
    {
        return $this->_primary;
    }

    /**
     *
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeySub[]
     */
    public function fetchSub()
    {
        return $this->_sub;
    }

    /**
     *
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\Uid[]
     */
    public function fetchUid()
    {
        return $this->_uid;
    }

    /**
     *
     * @param string $raw
     * @param string $password
     * @throws Exception
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\KeyRaw
     */
    private function _parseKeyByRaw($raw, $password = null)
    {
        if (!is_string($raw) || empty($raw)) {
            throw new \Exception('raw data is empty');
        }

        $process = $this->_gpg::callProcess(
            $this->_gpg,
            'gpg --with-fingerprint --batch --with-colons --import-options import-show --dry-run --import',
            $raw
        );

        if (preg_match_all(KeyPrimary::PREG_PATTERN_KEYPRIMARY_RAW, $process->getOutput(), $matches, PREG_SET_ORDER)) {

            if (count($matches) != 1) {
                throw new \Exception('multiple or non primary key found');
            }
            $match = current($matches);

            if (!in_array($match['type'], [KeyRaw::TYPE_PUBLIC, KeyRaw::TYPE_SECRET])) {
                throw new \Exception('unhandled key type "' . $match['type'] . '"');
            }
            $this->_type = $match['type'];

            // primary
            $this->_primary = KeyPrimary::factoryByMatch($matches[0]);

            // sub
            if (preg_match_all(KeySub::PREG_PATTERN_KEYSUB_RAW, $process->getOutput(), $matches, PREG_SET_ORDER)) {

                foreach ($matches as $match) {
                    $this->_sub[] = KeySub::factoryByMatch($match);
                }
            }

            // uid
            if (preg_match_all(Uid::PREG_PATTERN_UID, $process->getOutput(), $matches, PREG_SET_ORDER)) {

                foreach ($matches as $match) {
                    $this->_uid[] = Uid::factoryByMatch($match);
                }
            }
        }

        return $this;
    }

    /**
     *
     */
    public function import()
    {
        return $this->_gpg->import($this);
    }
}
