<?php

namespace UweLehmann\Gpg\Crypt\PublicKey;

use Zend\Mail\Address;
use Zend\Mail\AddressList;

use UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg\KeyRaw;

use UweLehmann\Process\Process;
use UweLehmann\Process\Pipes;
use UweLehmann\Process\Pipe\PipeAbstract;
use UweLehmann\Process\Pipe\Pipe;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 * @link http://www.gnupg.org/documentation/manuals/gnupg/Option-Index.html#Option-Index
 */
class Gpg
{
    /** @var string */
    const PREG_PATTERN_VERIFY = '~^'
        . 'gpg\: Signature made (?<create>.+)' . PHP_EOL
        . 'gpg\: \s+ using (?<type>(DSA|RSA)) key (?<fingerprint>[A-F0-9]{40})' . PHP_EOL
        . 'gpg\: (?<result>(Good|BAD)) signature from \"(?<owner>.+)\" .+' . PHP_EOL
        . '~'
    ;

    /** @var string */
    const PREG_PATTERN_CREATE = '~'
        . 'gpg\: .+' . PHP_EOL
        . 'gpg\: key (?<id>[A-F0-9]{16}) marked as ultimately trusted' . PHP_EOL
        . '(gpg\: .+' . PHP_EOL .')*'
        . 'gpg\: done' . PHP_EOL
        . '$~'
    ;

    /**
     *
     * @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg[]
     */
    private static $_instances = [];

    /** @var array */
    private $_env;

    /** @var string */
    private $_cwd;

    /** @var Key[]|false */
    private $_keyring = false;

    /**
     * returns instance of the Gpg object after running some checks
     *
     * @param array $options
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg
     * @throws \Exception
     */
    public static function getInstance(array $options)
    {
        // check options
        if (empty($options['gnupghome'])) {
            throw new \Exception('missing option "gnupghome"');
        }

        // check gnupghome path
        $path = realpath($options['gnupghome']);
        $index = md5($path);

        if (!is_dir($path)) {
            throw new \Exception('can not find path to keyring "' . $path . '"');
        } elseif (!is_writable($path)) {
            throw new \Exception('path to keyring "' . $path . '" is not writable');
        }


        if (!isset(static::$_instances[$index])
            || !static::$_instances[$index] instanceof Gpg
        ) {

            static::$_instances[$index] = new Gpg($path);
        }

        return static::$_instances[$index];
    }

    /**
     * executes command within the given Gpg environment
     *
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg $gpg
     * @param string $command
     * @param string $stdin
     * @param \UweLehmann\Process\Pipes|null $pipes
     * @return \UweLehmann\Process\Process
     */
    public static function callProcess(Gpg $gpg, $command, $stdin = null, Pipes $pipes = null)
    {
        $process = new Process($command, $stdin, $gpg->getCwd(), $gpg->getEnv());

        if (!empty($pipes)) {
            /** @var \UweLehmann\Process\Pipe\PipeAbstract $pipe */
            foreach ($pipes as $pipe) {
                $process->addPipe($pipe);
            }
        }

        $process->run();

        return $process;
    }

    /**
     * @param mixed $e0
     * @param mixed $e1
     * @return integer
     */
    private static function _sortByTimestamp($o0, $o1)
    {
        $e0 = $o0['timestamp'];
        $e1 = $o1['timestamp'];
        return (($e0==$e1) ? 0 : (($e0>$e1) ? 1 : -1));
    }

    /**
     * @param string $gnupghome
     * @throws \Exception
     */
    private function __construct($gnupghome)
    {
        $this->_cwd = (defined('APPLICATION_PATH') ? APPLICATION_PATH . '/data' : null);
        $this->_env = [
            'GNUPGHOME=' . $gnupghome,
        ];

        // workaround "Inappropriate ioctl for device"
        // @todo move to getInstance
        file_put_contents($gnupghome . DIRECTORY_SEPARATOR . 'gpg.conf', "use-agent\npinentry-mode loopback\n");
        file_put_contents($gnupghome . DIRECTORY_SEPARATOR . 'gpg-agent.conf', "allow-loopback-pinentry\n");
        $this::callProcess($this, 'echo RELOADAGENT | gpg-connect-agent');
    }

    /**
     *
     */
    private function _refreshKeyring()
    {
        $this->_keyring = Key::fetchAll($this);
    }

    /**
     * @return array
     */
    public function getEnv()
    {
        return $this->_env;
    }

    /**
     * @return string
     */
    public function getCwd()
    {
        return $this->_cwd;
    }

    /**
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key[]
     */
    public function getKeyring()
    {
        if ($this->_keyring === false || !is_array($this->_keyring)) {
            $this->_refreshKeyring();
        }

        return $this->_keyring;
    }

    // ------------------------------------------------------------------------

    /**
     *
     * @param string $type
     * @param string $fingerprint
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key|bool
     */
    public function findKeyByTypeAndFingerprint($type, $fingerprint)
    {
        switch ($type) {

            case Key::TYPE_PUBLIC:
                $keyPool = $this->fetchPublicKeys();
                break;

            case Key::TYPE_SECRET:
                $keyPool = $this->fetchSecretKeys();
                break;

            default:
                throw new Exception('unknown type "'. $type .'"');
        }

        $keyPool = array_filter(
            $keyPool,
            function ($key) use ($fingerprint) {

                if ($key->getPrimary()->getFingerprint() != $fingerprint) {
                    return false;
                }
                return true;
            },
            ARRAY_FILTER_USE_BOTH
        );

        if (empty($keyPool) || count($keyPool) != 1) {
            return false;
        }

        return current($keyPool);
    }

    /**
     *
     * @param string $email
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key[]
     */
    public function findPublicKeysByEmail($email)
    {
        $publicKeys = $this->fetchPublicKeys();

        // filter for email
        $publicKeys = array_filter(
            $publicKeys,
            function ($key) use ($email) {

                if (!$key instanceof Key || $key->getType() != Key::TYPE_PUBLIC) {
                    return false;
                }

                /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key\Uid $uid */
                foreach ($key->fetchUid() as $uid) {
                    if ($uid->getOwner()->getEMail() == $email) {
                        return true;
                    }
                }

                $owner = $key->getPrimary()->getOwner();
                if ($owner instanceof Address && $owner->getEMail() == $email) {
                    return true;
                }

                return false;
            }
        );

        usort($publicKeys, function(Key $o0, Key $o1) {

            $now = new \DateTime('now');

            // check expiry date first
            $e0 = ($o0->getPrimary()->getExpiry() < $now ? 1 : 0);
            $e1 = ($o1->getPrimary()->getExpiry() < $now ? 1 : 0);

            if ($e0 !== $e1) {

                return (($e0 > $e1) ? 1 : -1);
            } else {

                // check create date
                $c0 = $o0->getPrimary()->getCreate();
                $c1 = $o1->getPrimary()->getCreate();

                return (($c0 == $c1) ? 0 : (($c0 > $c1) ? 1 : -1));
            }
        });

        return $publicKeys;
    }

    /**
     *
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key[]
     */
    public function fetchPublicKeys()
    {
        return array_filter(
            $this->getKeyring(),
            function($key, $index) {
                return ($key instanceof Key && $key->getType() == Key::TYPE_PUBLIC);
            },
            ARRAY_FILTER_USE_BOTH
        );
    }

    /**
     *
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key[]
     */
    public function fetchSecretKeys()
    {
        return array_filter(
            $this->getKeyring(),
            function($key, $index) {
                return ($key instanceof Key && $key->getType() == Key::TYPE_SECRET);
            },
            ARRAY_FILTER_USE_BOTH
        );
    }

    /**
     *
     * @param \Zend\Mail\Address $address
     * @param string $password
     * @param string $comment
     * @param \DateInterval $livetime
     * @return string Key ID
     *
     * @todo createByKey(Key $key)
     */
    public function create(Address $address, $password, $comment = null, \DateInterval $livetime = null)
    {
        $expiry = new \DateTime();
        $expiry->add(is_null($livetime) ? new \DateInterval('P6M') : $livetime);

        $params = [
            'Key-Type' => 'DSA',
            'Key-Length' => 1024,
            'Key-Usage' => null,
            'Subkey-Type' => 'ELG-E',
            'Subkey-Length' => 1024,
            'Subkey-Usage' => null,
            'Name-Real' => $address->getName(),
            'Name-Comment' => $comment,
            'Name-Email' => $address->getEmail(),
            'Expire-Date' => $expiry->format('Y-m-d'),
            'Passphrase' => $password,
        ];

        array_walk($params, function(&$value, $key) {
            $value = (!empty($value) ? "{$key}: {$value}" : null);
        });

        $input = '%echo Generating a default key' . PHP_EOL
               . implode(PHP_EOL, array_filter($params)) . PHP_EOL
               . '%commit' . PHP_EOL
               . '%echo done' . PHP_EOL
        ;

        $process = $this::callProcess($this, 'gpg --batch --no-tty --gen-key', $input);

        $matches = [];
        if (!preg_match(self::PREG_PATTERN_CREATE, $process->getError(), $matches)) {
            return false;
        }

        $this->_refreshKeyring();

        return $matches['id'];
    }

    /**
     *
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg\KeyRaw $raw
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key
     *
     * @todo some checks and error handling
     */
    public function import(KeyRaw $raw)
    {
        $process = $this::callProcess($this, 'gpg --import --batch --with-colons --no-tty', $raw->getRaw());

        /*
gpg: key 71258AF9: public key "User Beta <beta@example.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1

         */
        //$process->getError();

        $this->_refreshKeyring();

        return $this->findKeyByTypeAndFingerprint($raw->getType(), $raw->getPrimary()->getFingerprint());
    }

    /**
     *
     * @param string $data
     * @param \Zend\Mail\AddressList $recipients
     * @param boolean $armor [optional]
     * @return string
     * @throws \Exception
     */
    public function encrypt($data, AddressList $recipients, $armor = false)
    {
        $params = [
            '--encrypt',
            '--no-secmem-warning',
            '--always-trust',
            '--no-tty',
            '--batch',
        ];

        // add recipients
        foreach ($recipients as $recipient) {

            if (!$recipient instanceof Address) {
                throw new \Exception('expecting only objects of type Zend\Mail\Address');
            }
            $params[] = '--recipient ' . escapeshellarg($recipient->getEmail());
        }

        if ($armor === true) {
            $params[] = '--armor';
        }

        return $this::callProcess(
            $this,
            'gpg ' . implode(' ', $params), "{$data}"
        )->getOutput();
    }

    /**
     *
     * @param string $data
     * @param string $password
     */
    public function decrypt($data, $password = null)
    {
        return $this::callProcess(
            $this,
            'gpg --decrypt --yes --no-secmem-warning --always-trust --no-tty --batch --passphrase-fd 0',
            $password . PHP_EOL . $data
        )->getOutput();
    }

    /**
     *
     * @param string $data
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key $key
     * @param string $password
     * @param boolean $armor
     * @return string|false
     */
    public function detachedSignature($data, Key $key, $password = null, $armor = false)
    {
        if (!$key instanceof Key || $key->getType() != Key::TYPE_SECRET) {
            throw new Exception('expecting secret key');
        }

        $params = [
            '--detach-sign',
            '--local-user ' . $key->getPrimary()->getFingerprint(),
            '--no-secmem-warning',
            '--always-trust',
            '--no-tty',
            '--batch',
        ];

        if (!empty($password)) {
            $params[] = '--passphrase-fd 0';
            $data = $password . PHP_EOL . $data;
        }

        if ($armor === true) {
            $params[] = '--armor';
        }

        return $this::callProcess($this, 'gpg ' . implode(' ', $params), $data)
            ->getOutput();
    }


    /**
     *
     * @param string $data
     * @param string $signature
     * @return boolean
     */
    public function verify($data, $signature)
    {
        $pipe3 = new Pipe(PipeAbstract::MODE_READ);
        $pipe3->setData($data);

        $pipe4 = new Pipe(PipeAbstract::MODE_READ);
        $pipe4->setData($signature);

        $process = $this::callProcess(
            $this,
            'gpg --verify --enable-special-filenames --no-secmem-warning --always-trust --no-tty --batch -- \'-&4\' \'-&3\'',
            null,
            new Pipes([$pipe3, $pipe4])
        );

        $matches = [];
        if (!preg_match(self::PREG_PATTERN_VERIFY, $process->getError(), $matches)) {
            throw new \Exception('verifying data failed');
        }

//        $address = KeyAbstract::getAddressFromOwner($matches['owner']);
//        $date = \DateTime::createFromFormat('D M d H:i:s Y O', $matches['create']);
//        $fingerprint = $matches['fingerprint'];
//        $type = $matches['type'];

        return ($matches['result'] == 'Good');
    }
}
