<?php

use Leenooks\OpenPGP;

class MessageVerification extends PHPUnit\Framework\TestCase {
  public function oneMessageRSA($pkey, $path) {
    $pkeyM = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $pkey));
    $m = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
    $verify = new OpenPGP\Crypt\RSA($pkeyM);
    $this->assertSame($verify->verify($m), $m->signatures());
  }

  public function testUncompressedOpsRSA() {
    $this->oneMessageRSA('pubring.gpg', 'uncompressed-ops-rsa.gpg');
  }

  public function testCompressedSig() {
    $this->oneMessageRSA('pubring.gpg', 'compressedsig.gpg');
  }

  public function testCompressedSigZLIB() {
    $this->oneMessageRSA('pubring.gpg', 'compressedsig-zlib.gpg');
  }

  public function testCompressedSigBzip2() {
    $this->oneMessageRSA('pubring.gpg', 'compressedsig-bzip2.gpg');
  }

  public function testSigningMessages() {
    $wkey = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
    $data = new OpenPGP\LiteralDataPacket('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
    $sign = new OpenPGP\Crypt\RSA($wkey);
    $m = $sign->sign($data)->to_bytes();
    $reparsedM = OpenPGP\Message::parse($m);
    $this->assertSame($sign->verify($reparsedM), $reparsedM->signatures());
  }

/*
  public function testUncompressedOpsDSA() {
    $this->oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa.gpg');
  }

  public function testUncompressedOpsDSAsha384() {
    $this->oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa-sha384.gpg');
  }
*/
}


class KeyVerification extends PHPUnit\Framework\TestCase {
  public function oneKeyRSA($path) {
    $m = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
    $verify = new OpenPGP\Crypt\RSA($m);
    $this->assertSame($verify->verify($m), $m->signatures());
  }

  public function testHelloKey() {
    $this->oneKeyRSA("helloKey.gpg");
  }
}


class Decryption extends PHPUnit\Framework\TestCase {
  public function oneSymmetric($pass, $cnt, $path) {
    $m = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
    $m2 = OpenPGP\Crypt\Symmetric::decryptSymmetric($pass, $m);
    while($m2[0] instanceof OpenPGP\CompressedDataPacket) $m2 = $m2[0]->data;
    foreach($m2 as $p) {
      if($p instanceof OpenPGP\LiteralDataPacket) {
        $this->assertEquals($p->data, $cnt);
      }
    }
  }

  public function testDecrypt3DES() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-3des.gpg");
  }

  public function testDecryptCAST5() { // Requires mcrypt or openssl
    $this->oneSymmetric("hello", "PGP\n", "symmetric-cast5.gpg");
  }

  public function testDecryptBlowfish() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-blowfish.gpg");
  }

  public function testDecryptAES() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-aes.gpg");
  }

  public function testDecryptTwofish() {
    if(OpenPGP\Crypt\Symmetric::getCipher(10)[0]) {
      $this->oneSymmetric("hello", "PGP\n", "symmetric-twofish.gpg");
    }
  }

  public function testDecryptSessionKey() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-with-session-key.gpg");
  }

  public function testDecryptNoMDC() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-no-mdc.gpg");
  }

  public function testDecryptAsymmetric() {
    $m = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/hello.gpg'));
    $key = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
    $decryptor = new OpenPGP\Crypt\RSA($key);
    $m2 = $decryptor->decrypt($m);
    while($m2[0] instanceof OpenPGP\CompressedDataPacket) $m2 = $m2[0]->data;
    foreach($m2 as $p) {
      if($p instanceof OpenPGP\LiteralDataPacket) {
        $this->assertEquals($p->data, "hello\n");
      }
    }
  }

  public function testDecryptRoundtrip() {
    $m = new OpenPGP\Message(array(new OpenPGP\LiteralDataPacket("hello\n")));
    $key = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
    $em = OpenPGP\Crypt\Symmetric::encrypt($key, $m);

    foreach($key as $packet) {
	   if(!($packet instanceof OpenPGP\SecretKeyPacket)) continue;
      $decryptor = new OpenPGP\Crypt\RSA($packet);
      $m2 = $decryptor->decrypt($em);

      foreach($m2 as $p) {
        if($p instanceof OpenPGP\LiteralDataPacket) {
          $this->assertEquals($p->data, "hello\n");
        }
      }
    }
  }

  public function testDecryptSecretKey() {
    $key = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/encryptedSecretKey.gpg'));
    $skey = OpenPGP\Crypt\Symmetric::decryptSecretKey("hello", $key[0]);
    $this->assertSame(!!$skey, true);
  }

  public function testEncryptSecretKeyRoundtrip() {
    $key = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
    $enkey = OpenPGP\Crypt\Symmetric::encryptSecretKey("password", $key[0]);
    $skey = OpenPGP\Crypt\Symmetric::decryptSecretKey("password", $enkey);
    $this->assertEquals($key[0], $skey);
  }

  public function testAlreadyDecryptedSecretKey() {
    $this->expectException(Exception::class);
    $this->expectExceptionMessage("Data is already unencrypted");
    $key = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
    OpenPGP\Crypt\Symmetric::decryptSecretKey("hello", $key[0]);
  }
}

class Encryption extends PHPUnit\Framework\TestCase {
  public function oneSymmetric($algorithm) {
    $data = new OpenPGP\LiteralDataPacket('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
    $encrypted = OpenPGP\Crypt\Symmetric::encrypt('secret', new OpenPGP\Message(array($data)), $algorithm);
    $encrypted = OpenPGP\Message::parse($encrypted->to_bytes());
    $decrypted = OpenPGP\Crypt\Symmetric::decryptSymmetric('secret', $encrypted);
    $this->assertEquals($decrypted[0]->data, 'This is text.');
  }

  public function testEncryptSymmetric3DES() {
    $this->oneSymmetric(2);
  }

  public function testEncryptSymmetricCAST5() {
    $this->oneSymmetric(3);
  }

  public function testEncryptSymmetricBlowfish() {
    $this->oneSymmetric(4);
  }

  public function testEncryptSymmetricAES128() {
    $this->oneSymmetric(7);
  }

  public function testEncryptSymmetricAES192() {
    $this->oneSymmetric(8);
  }

  public function testEncryptSymmetricAES256() {
    $this->oneSymmetric(9);
  }

  public function testEncryptSymmetricTwofish() {
    if(OpenPGP\Crypt\Symmetric::getCipher(10)[0]) {
      $this->oneSymmetric(10);
    }
  }

  public function testEncryptAsymmetric() {
    $key = OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
    $data = new OpenPGP\LiteralDataPacket('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
    $encrypted = OpenPGP\Crypt\Symmetric::encrypt($key, new OpenPGP\Message(array($data)));
    $encrypted = OpenPGP\Message::parse($encrypted->to_bytes());
    $decryptor = new OpenPGP\Crypt\RSA($key);
    $decrypted = $decryptor->decrypt($encrypted);
    $this->assertEquals($decrypted[0]->data, 'This is text.');
  }
}
