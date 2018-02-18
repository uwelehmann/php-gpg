<?php

namespace UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key;

/**
 * @todo not in use; check if there is any need for this
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class Fingerprint
{
    /** @var string */
    const FPR = 'fpr';

    /** @var string */
    const PREG_PATTERN_FPR = '~'
        . 'fpr\:'
        . '([^\:]*\:){8}'
        . '(?<fingerprint>[0-9A-F]{40})\:'
        . '~'
    ;

    /** @var string */
    protected $_fingerprint;

    /**
     *
     * @param array $match
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\KeyAbstract
     */
    public static function factoryByMatch(array $match)
    {
        $fingerprint = new static();
        $fingerprint->setFingerprint($match['fingerprint']);

        return $fingerprint;
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
}
