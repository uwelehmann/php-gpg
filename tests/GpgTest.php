<?php

namespace UweLehmann\GpgTest;

use Zend\Mail;
use Zend\Mime;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg;
use UweLehmann\Process\Process;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 * @covers \UweLehmann\Gpg\Crypt\PublicKey\Gpg
 */
class GpgTest extends \PHPUnit\Framework\TestCase
{
    // GnuPG home folders to store keys
    const GNUPG_HOME_ALPHA = __DIR__ . '/gnupg/.alpha';
    const GNUPG_HOME_BETA = __DIR__ . '/gnupg/.beta';
    const GNUPG_HOME_GAMMA = __DIR__ . '/gnupg/.gamma';

    // raw message output
    const RAW = __DIR__ . '/raw';

    // GnuPG passwords
    const GNUPG_PW_ALPHA = 'pwAlpha';
    const GNUPG_PW_BETA = 'pwBeta';
    const GNUPG_PW_GAMMA = 'pwGamma';

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpgAlpha;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpgBeta;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpgGamma;

    /**
     *
     */
    public function setUp()
    {
        parent::setUp();

        $this->_gpgAlpha = Gpg::getInstance([
            'gnupghome' => self::GNUPG_HOME_ALPHA,
        ]);

        $this->_gpgBeta = Gpg::getInstance([
            'gnupghome' => self::GNUPG_HOME_BETA,
        ]);

        $this->_gpgGamma = Gpg::getInstance([
            'gnupghome' => self::GNUPG_HOME_GAMMA,
        ]);
    }

    /**
     * set up 3 gnupg home paths
     */
    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        // check and create gnupghome folders
        if (realpath(self::GNUPG_HOME_ALPHA) === false && mkdir(self::GNUPG_HOME_ALPHA, 0700, true) === false) {
            throw new \Exception('can\'t create folder "' . self::GNUPG_HOME_ALPHA . '" for gpg home for user alpha');
        }
        elseif (realpath(self::GNUPG_HOME_BETA) === false && mkdir(self::GNUPG_HOME_BETA, 0700, true) === false) {
            throw new \Exception('can\'t create folder "' . self::GNUPG_HOME_BETA . '" for gpg home for user beta');
        }
        elseif (realpath(self::GNUPG_HOME_GAMMA) === false && mkdir(self::GNUPG_HOME_GAMMA, 0700, true) === false) {
            throw new \Exception('can\'t create folder "' . self::GNUPG_HOME_GAMMA . '" for gpg home for user gamma');
        }
    }

    /**
     * remove gnupg home paths
     */
    public static function tearDownAfterClass()
    {
        parent::tearDownAfterClass();

        // remove gnupgfolders
        $process = new Process(
            'rm -rf ' . self::GNUPG_HOME_ALPHA
            . ' ' . self::GNUPG_HOME_BETA
            . ' ' . self::GNUPG_HOME_GAMMA
        );
        $process->run();
    }

    /**
     * creates keypairs for following tests
     *
     * @TODO uwe@raspberrypi:/var/www/zend.nerd.cloudns.org $ phpunit --testsuite vendor-nxclass-gpgmail
     */
    public function testCreateKeypairs()
    {
        // alpha
        $keyId = $this->_gpgAlpha->create(
            new Mail\Address('alpha@example.org', 'User Alpha'),
            self::GNUPG_PW_ALPHA
        );
        $this->assertFalse(($keyId === false));
        $this->assertStringMatchesFormat('%x', $keyId);

        $publicKeysAlpha = $this->_gpgAlpha->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysAlpha));
        $this->assertCount(1, $publicKeysAlpha);

        // beta
        $keyId = $this->_gpgBeta->create(
            new Mail\Address('beta@example.org', 'User Beta'),
            self::GNUPG_PW_BETA
        );
        $this->assertFalse(($keyId === false));
        $this->assertStringMatchesFormat('%x', $keyId);

        $publicKeysBeta = $this->_gpgBeta->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysBeta));
        $this->assertCount(1, $publicKeysBeta);

        // gamma
        $keyId = $this->_gpgGamma->create(
            new Mail\Address('gamma@example.org', 'User Gamma'),
            self::GNUPG_PW_GAMMA
        );
        $this->assertFalse(($keyId === false));
        $this->assertStringMatchesFormat('%x', $keyId);

        $publicKeysGamma = $this->_gpgGamma->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysGamma));
        $this->assertCount(1, $publicKeysGamma);
    }

    /**
     * @depends testCreateKeypairs
     */
    public function testRaw()
    {
        // public
        $publicKeysAlpha = $this->_gpgAlpha->fetchPublicKeys();
        $publicKeyAlpha = array_pop($publicKeysAlpha);
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyAlpha);
        $this->assertTrue(($publicKeyAlpha->getType() == Gpg\Key::TYPE_PUBLIC));

        $publicKeyAlphaRaw = $publicKeyAlpha->export();
        $this->assertNotEmpty($publicKeyAlphaRaw);

        $publicKeyAlphaFromRaw = new Gpg\KeyRaw($this->_gpgAlpha, $publicKeyAlphaRaw);

        $this->assertInstanceOf(Gpg\KeyRaw::class, $publicKeyAlphaFromRaw);
        $this->assertTrue(($publicKeyAlpha->getType() == $publicKeyAlphaFromRaw->getType()));
        $this->assertTrue(($publicKeyAlpha->getPrimary()->getFingerprint() == $publicKeyAlphaFromRaw->getPrimary()->getFingerprint()));

/*        // secret
        $secretKeysAlpha = $this->_gpgAlpha->fetchSecretKeys();
        $secretKeyAlpha = array_pop($secretKeysAlpha);
        $this->assertInstanceOf(Gpg\Key::class, $secretKeyAlpha);
        $this->assertTrue(($secretKeyAlpha->getType() == Gpg\Key::TYPE_SECRET));

        $secretKeyAlphaRaw = $secretKeyAlpha->export(self::GNUPG_PW_ALPHA);
        $this->assertNotEmpty($secretKeyAlphaRaw);

        $secretKeyAlphaFromRaw = new Gpg\KeyRaw($this->_gpgAlpha, $secretKeyAlphaRaw, self::GNUPG_PW_ALPHA);

        $this->assertInstanceOf(Gpg\KeyRaw::class, $secretKeyAlphaFromRaw);
        $this->assertTrue(($secretKeyAlpha->getType() == $secretKeyAlphaFromRaw->getType()));
        $this->assertTrue(($secretKeyAlpha->getPrimary()->getFingerprint() == $secretKeyAlphaFromRaw->getPrimary()->getFingerprint()));
*/
    }

    /**
     * @depends testCreateKeypairs
     */
    public function testExportImport()
    {
        // export
        // .. alpha
        $publicKeysAlpha = $this->_gpgAlpha->fetchPublicKeys();
        $publicKeyAlpha = array_pop($publicKeysAlpha);
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyAlpha);
        $this->assertTrue(($publicKeyAlpha->getType() == Gpg\Key::TYPE_PUBLIC));

        $publicKeyAlphaRaw = $publicKeyAlpha->export();
        $this->assertNotEmpty($publicKeyAlphaRaw);

        $publicKeyAlphaFromRaw = new Gpg\KeyRaw($this->_gpgAlpha, $publicKeyAlphaRaw);
        $this->assertInstanceOf(Gpg\KeyRaw::class, $publicKeyAlphaFromRaw);
        $this->assertTrue(($publicKeyAlpha->getType() == $publicKeyAlphaFromRaw->getType()));
        $this->assertTrue(($publicKeyAlpha->getPrimary()->getFingerprint() == $publicKeyAlphaFromRaw->getPrimary()->getFingerprint()));

        // .. beta
        $publicKeysBeta = $this->_gpgBeta->fetchPublicKeys();
        $publicKeyBeta = array_pop($publicKeysBeta);
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyBeta);
        $this->assertTrue(($publicKeyBeta->getType() == Gpg\Key::TYPE_PUBLIC));

        $publicKeyBetaRaw = $publicKeyBeta->export();
        $this->assertNotEmpty($publicKeyBetaRaw);

        $publicKeyBetaFromRaw = new Gpg\KeyRaw($this->_gpgBeta, $publicKeyBetaRaw);
        $this->assertInstanceOf(Gpg\KeyRaw::class, $publicKeyBetaFromRaw);
        $this->assertTrue(($publicKeyBeta->getType() == $publicKeyBetaFromRaw->getType()));
        $this->assertTrue(($publicKeyBeta->getPrimary()->getFingerprint() == $publicKeyBetaFromRaw->getPrimary()->getFingerprint()));

        // .. gamma
        $publicKeysGamma = $this->_gpgGamma->fetchPublicKeys();
        $publicKeyGamma = array_pop($publicKeysGamma);
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyGamma);
        $this->assertTrue(($publicKeyGamma->getType() == Gpg\Key::TYPE_PUBLIC));

        $publicKeyGammaRaw = $publicKeyGamma->export();
        $this->assertNotEmpty($publicKeyGammaRaw);

        $publicKeyGammaFromRaw = new Gpg\KeyRaw($this->_gpgGamma, $publicKeyGammaRaw);
        $this->assertInstanceOf(Gpg\KeyRaw::class, $publicKeyGammaFromRaw);
        $this->assertTrue(($publicKeyGamma->getType() == $publicKeyGammaFromRaw->getType()));
        $this->assertTrue(($publicKeyGamma->getPrimary()->getFingerprint() == $publicKeyGammaFromRaw->getPrimary()->getFingerprint()));

        // import
        // .. alpha
        $this->_gpgAlpha->import($publicKeyBetaFromRaw);
        $this->_gpgAlpha->import($publicKeyGammaFromRaw);

        $publicKeysAlpha = $this->_gpgAlpha->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysAlpha));
        $this->assertCount(3, $publicKeysAlpha);

        // .. beta
        $this->_gpgBeta->import($publicKeyAlphaFromRaw);
        $this->_gpgBeta->import($publicKeyGammaFromRaw);

        $publicKeysBeta = $this->_gpgBeta->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysBeta));
        $this->assertCount(3, $publicKeysBeta);

        // .. gamma
        $this->_gpgGamma->import($publicKeyAlphaFromRaw);
        $this->_gpgGamma->import($publicKeyBetaFromRaw);

        $publicKeysGamma = $this->_gpgGamma->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysGamma));
        $this->assertCount(3, $publicKeysGamma);
    }

    /**
     * @depends testExportImport
     */
    public function testEncryptDecrypt()
    {
        // get keys for encryption
        $secretKeysAlpha = $this->_gpgAlpha->fetchSecretKeys();
        /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key $fromAlpha */
        $fromAlpha = array_pop($secretKeysAlpha);
        $this->assertInstanceOf(Gpg\Key::class, $fromAlpha);
        $this->assertTrue(($fromAlpha->getType() === Gpg\Key::TYPE_SECRET));

        $publicKeysToBeta = $this->_gpgAlpha->findPublicKeysByEmail('beta@example.org');
        /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key $toBeta */
        $toBeta = array_pop($publicKeysToBeta);
        $this->assertInstanceOf(Gpg\Key::class, $toBeta);
        $this->assertTrue(($toBeta->getType() === Gpg\Key::TYPE_PUBLIC));

        $publicKeysToGamma = $this->_gpgAlpha->findPublicKeysByEmail('gamma@example.org');
        /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key $toGamma */
        $toGamma = array_pop($publicKeysToGamma);
        $this->assertInstanceOf(Gpg\Key::class, $toGamma);
        $this->assertTrue(($toGamma->getType() === Gpg\Key::TYPE_PUBLIC));

        // recipients
        $list = new Mail\AddressList();
        $list->addMany([
            current($toBeta->fetchUid())->getOwner(),
            current($toGamma->fetchUid())->getOwner(),
        ]);
        $message = $this->_buildTestMessage(current($fromAlpha->fetchUid())->getOwner(), $list);

        // encrypt
        $messageEncrypted = $this->_gpgAlpha->encrypt($message->toString(), $list, true);
        $this->assertNotEmpty($messageEncrypted);
        $this->assertRegExp('~^\-{5}BEGIN PGP MESSAGE\-{5}[^\-]+\-{5}END PGP MESSAGE\-{5}$~', $messageEncrypted);

        // sign
        $messageSignature = $this->_gpgAlpha->detachedSignature($messageEncrypted, $fromAlpha, self::GNUPG_PW_ALPHA, true);
        $this->assertNotEmpty($messageSignature);
        $this->assertRegExp('~^\-{5}BEGIN PGP SIGNATURE\-{5}[^\-]+\-{5}END PGP SIGNATURE\-{5}$~', $messageSignature);

        // verify
        $verifiedBeta = $this->_gpgBeta->verify($messageEncrypted, $messageSignature);
        $this->assertTrue($verifiedBeta);
        $verifiedGamma = $this->_gpgGamma->verify($messageEncrypted, $messageSignature);
        $this->assertTrue($verifiedGamma);

        // decrypt
        $messageDecryptedBeta = $this->_gpgBeta->decrypt($messageEncrypted, self::GNUPG_PW_BETA);
        $this->assertEquals($messageDecryptedBeta, $message->toString());
        $messageDecryptedGamma = $this->_gpgGamma->decrypt($messageEncrypted, self::GNUPG_PW_GAMMA);
        $this->assertEquals($messageDecryptedGamma, $message->toString());
    }

    /**
     * @see https://framework.zend.com/manual/2.4/en/modules/zend.mail.read.html#zend-mail-read
     * @param \Zend\Mail\Address $from
     * @param \Zend\Mail\AddressList $to
     * @param Gpg\Key $publicKey
     * @return \Zend\Mail\Message
     */
    private function _buildTestMessage(Mail\Address $from, Mail\AddressList $to, Gpg\Key $publicKey = null)
    {
        // bulid alternative message parts
        $textPart = new Mime\Part('LoremIpsum' . PHP_EOL . $this->_getLoremIpsum());
        $textPart->setType(Mime\Mime::TYPE_TEXT)
            ->setEncoding(Mime\Mime::ENCODING_QUOTEDPRINTABLE)
            ->setCharset('utf-8')
        ;

        $htmlPart = new Mime\Part('<h1>LoremIpsum</h1><p>' . $this->_getLoremIpsum() . '</p>');
        $htmlPart->setType(Mime\Mime::TYPE_HTML)
            ->setEncoding(Mime\Mime::ENCODING_QUOTEDPRINTABLE)
            ->setCharset('utf-8')
        ;

        $alternative = new Mime\Message();
        $alternative->setParts([$textPart, $htmlPart]);

        $alternativeMessage = new Mail\Message();
        $alternativeMessage->setBody($alternative);
        /** @var \Zend\Mail\Header\ContentType $contentTypeHeader */
        $contentTypeHeader = $alternativeMessage->getHeaders()->get('Content-Type');
        $contentTypeHeader->setType('multipart/alternative');

        if (!$publicKey instanceof Gpg\Key
            || $publicKey->getType() != Gpg\Key::TYPE_PUBLIC
        ) {

            $alternativeMessage->setFrom($from)
                ->setTo($to)
                ->setSubject('LoremIpsum')
            ;

            return $alternativeMessage;
        }

        // attach public key to an multipart/mixed message
        $filename = $publicKey->getPrimary()->getOwner()->getName()
                  . ' ' . $publicKey->getPrimary()->getOwner()->getEmail()
                  . ' (0x' . $publicKey->getPrimary()->getId() . ')'
                  . ' pub.asc'
        ;
        $publicKeyPart = new Mime\Part($publicKey->export());
        $publicKeyPart->setType('application/pgp-keys')
            ->setFileName($filename)
            ->setDisposition(Mime\Mime::DISPOSITION_ATTACHMENT)
            ->setEncoding(Mime\Mime::ENCODING_BASE64)
        ;

        /** @var \Zend\Mail\Header\ContentType $contentTypeHeader */
        $contentTypeHeader = $alternativeMessage->getHeaders()->get('Content-Type');

        $alternativeMessagePart = new Mime\Part($alternativeMessage->getBodyText());
        $alternativeMessagePart->setType($contentTypeHeader->getType());
        $alternativeMessagePart->setBoundary($contentTypeHeader->getParameter('boundary'));

        $mixed = new Mime\Message();
        $mixed->setParts([$alternativeMessagePart, $publicKeyPart]);

        $mixedMessage = new Mail\Message();
        $mixedMessage->setBody($mixed);
        /** @var \Zend\Mail\Header\ContentType $contentTypeHeader */
        $contentTypeHeader = $mixedMessage->getHeaders()->get('Content-Type');
        $contentTypeHeader->setType('multipart/mixed');

        $mixedMessage->setFrom($from)
            ->setTo($to)
            ->setSubject('LoremIpsum')
        ;

        return $mixedMessage;
    }

    /**
     * @return string
     */
    private function _getLoremIpsum()
    {
        return 'Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquid ex ea commodi consequat. Quis aute iure reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint obcaecat cupiditat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';
    }
}
