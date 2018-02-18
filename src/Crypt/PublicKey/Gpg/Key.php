<?php

namespace UweLehmann\Gpg\Crypt\PublicKey\Gpg;

use UweLehmann\Gpg\Crypt\PublicKey\Gpg;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyPrimary;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeySub;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\Uid;

use UweLehmann\Process\Process;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class Key
{
    /** @var string */
    const TYPE_PUBLIC = 'pub';

    /** @var string */
    const TYPE_SECRET = 'sec';

    /** @var string */
    const PREG_PATTERN_LIST_KEYS = '~'
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
        . '(?<unknown2>[^\:]+)?\:'
        . '(?<capability>[escaESCA]*)\:'
        . '([^\:]*\:){6}'
        . PHP_EOL
        . 'fpr\:'
        . '([^\:]*\:){8}'
        . '(?<fingerprint>[0-9A-F]{40})\:'
        . '~'
    ;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpg;

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
     * @param string $type
     * @throws \Exception
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key[]
     */
    public static function fetchAll(Gpg $gpg, $type = null)
    {
        if (!empty($type) && !in_array($type, [static::TYPE_SECRET, static::TYPE_PUBLIC])) {
            throw new Exception('');
        }

        $keys = [];

        // fetch secret
        if (empty($type) || $type == static::TYPE_SECRET) {

            $process = Process::factory(
                'gpg --with-colons --with-fingerprint --batch --list-secret-keys',
                null,
                $gpg->getCwd(),
                $gpg->getEnv()
            );
            $process->run();

            $matches = [];
            if (preg_match_all(static::PREG_PATTERN_LIST_KEYS, $process->getOutput(), $matches, PREG_SET_ORDER)) {

                foreach ($matches as $match) {
                    $keys[] = new static($gpg, $match['fingerprint'], static::TYPE_SECRET);
                }
            }
        }

        // fetch public
        if (empty($type) || $type == static::TYPE_PUBLIC) {

            $process = Process::factory(
                'gpg --with-colons --with-fingerprint --batch --list-keys',
                null,
                $gpg->getCwd(),
                $gpg->getEnv()
            );
            $process->run();

            $matches = [];
            if (preg_match_all(static::PREG_PATTERN_LIST_KEYS, $process->getOutput(), $matches, PREG_SET_ORDER)) {

                foreach ($matches as $match) {
                    $keys[] = new static($gpg, $match['fingerprint'], static::TYPE_PUBLIC);
                }
            }
        }

        return $keys;
    }

    /**
     *
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg $gpg
     * @param string $fingerprint
     * @param string $type
     * @throws \Exception
     */
    public function __construct(Gpg $gpg, $fingerprint, $type)
    {
        $this->_gpg = $gpg;
        $this->_type = $type;

        $this->_parseKeyByFingerprint($fingerprint, $type);
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
     * @param string $fingerprint
     * @param string $type
     * @throws \Exception
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key
     */
    private function _parseKeyByFingerprint($fingerprint, $type)
    {
        if (!in_array($type, [self::TYPE_SECRET, self::TYPE_PUBLIC])) {
            throw new \Exception('');
        }

        if (empty($fingerprint) || !preg_match('~^[A-F0-9]{40}$~', $fingerprint) ) {
            throw new \Exception('');
        }

        $command = null;

        switch ($type) {
            case self::TYPE_SECRET:
                $command = 'gpg --with-colons --with-fingerprint --batch --list-secret-keys ' . $fingerprint;
                break;
            case self::TYPE_PUBLIC:
                $command = 'gpg --with-colons --with-fingerprint --batch --list-keys ' . $fingerprint;
                break;
        }

        $process = Process::factory($command, null, $this->_gpg->getCwd(), $this->_gpg->getEnv());
        $process->run();

        // primary
        $matches = [];
        if (preg_match_all(KeyPrimary::PREG_PATTERN_KEYPRIMARY, $process->getOutput(), $matches, PREG_SET_ORDER)) {

            if (count($matches) != 1) {
                throw new \Exception('multiple primary keys found');
            }

            $this->_primary = KeyPrimary::factoryByMatch($matches[0]);
        }
        else {
            throw new \Exception('no primary key found');
        }

        // sub
        $matches = [];
        if (preg_match_all(KeySub::PREG_PATTERN_KEYSUB, $process->getOutput(), $matches, PREG_SET_ORDER)) {

            foreach ($matches as $match) {
                $this->_sub[] = KeySub::factoryByMatch($match);
            }
        }

        // uid
        $matches = [];
        if (preg_match_all(Uid::PREG_PATTERN_UID, $process->getOutput(), $matches, PREG_SET_ORDER)) {

            foreach ($matches as $match) {
                $this->_uid[] = Uid::factoryByMatch($match);
            }
        }
        else {
            throw new \Exception('no UID in key found');
        }

        return $this;
    }

    /**
     *
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key
     */
    private function _refreshKey()
    {
        $fingerprint = $this->_primary->getFingerprint();

        $this->_primary = null;
        $this->_sub = [];
        $this->_uid = [];

        return $this->_parseKeyByFingerprint($fingerprint, $this->_type);
    }

    /**
     *
     * @var string $password
     * @return string
     */
    public function export($password = null)
    {
        $command = null;
        $data = null;

        $keyPrimary = $this->getPrimary();
        if (!$keyPrimary instanceof KeyPrimary) {
            throw new \Exception('missing primary key');
        }

        switch ($this->getType()) {
            case self::TYPE_SECRET:
                $command = 'gpg -a --batch --no-tty --passphrase-fd 0 --export-secret-keys ' . $this->getPrimary()->getFingerprint();
                if (!empty($password))  {
                    $data = $password . PHP_EOL;
                }
                break;

            case self::TYPE_PUBLIC:
                $command = 'gpg -a --batch --no-tty --export ' . $this->getPrimary()->getFingerprint();
                break;

            default:
                throw new \Exception('unknown key type');
        }

        return $this->_gpg::callProcess($this->_gpg, $command, $data)->getOutput();
    }
}
