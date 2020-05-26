<?php
declare(strict_types=1);

namespace Nexmo\JWT;

/**
 * Mock time call to help with testing
 */
function time()
{
    return 1590087267;
}

namespace NexmoTest\JWT;

use Ramsey\Uuid\Uuid;
use Lcobucci\JWT\Parser;
use Nexmo\JWT\TokenGenerator;
use PHPUnit\Framework\TestCase;
use Nexmo\JWT\Exception\InvalidJTIException;
use stdClass;

class TokenGeneratorTest extends TestCase
{
    /**
     * Generating a token with just an App ID and a Private Key
     */
    public function testGenerateSimpleToken()
    {
        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertSame('RS256', $parsedToken->getHeader('alg'));
        $this->assertSame('JWT', $parsedToken->getHeader('typ'));
        $this->assertSame(1590087267, $parsedToken->getClaim('iat'));
        $this->assertSame(1590087267 + 900, $parsedToken->getClaim('exp'));
        $this->assertTrue(Uuid::isValid($parsedToken->getClaim('jti')));
        $this->assertFalse($parsedToken->hasHeader('acl'));
        $this->assertFalse($parsedToken->hasHeader('nbf'));
    }

    /**
     * User should be able to override the expiration time
     */
    public function testCanChangeExpirationTime()
    {
        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->setExpirationTime(50);
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertSame(1590087267 + 50, $parsedToken->getClaim('exp'));
    }

    /**
     * User should be able to supply their own JWT ID
     */
    public function testCanSetJWTID()
    {
        $uuid = Uuid::uuid4()->toString();

        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->setJTI($uuid);
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertTrue(Uuid::isValid($parsedToken->getClaim('jti')));
        $this->assertSame($uuid, $parsedToken->getClaim('jti'));
    }

    /**
     * JWT ID must reject anything that isn't a UUIDv4
     */
    public function testRejectsInvalidJTI()
    {
        $this->expectException(InvalidJTIException::class);

        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->setJTI('abcd');
    }

    /**
     * User can see a "Not Before" time
     */
    public function testCanSetNBF()
    {
        $nbf = strtotime('2025-01-01 00:00:00');

        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->setNotBefore($nbf);
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertSame($nbf, $parsedToken->getClaim('nbf'));
    }

    /**
     * User can set bulk path ACL information
     */
    public function testCanSetACLPaths()
    {
        $paths = [
            '/*/users/**',
            '/*/conversations/**'
        ];

        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->setPaths($paths);
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertTrue($parsedToken->hasClaim('acl'));
        $acl = $parsedToken->getClaim('acl');

        $this->assertCount(2, (array) $acl->paths);
        $this->assertTrue($acl->paths->{$paths[0]} instanceof stdClass);
        $this->assertTrue($acl->paths->{$paths[1]} instanceof stdClass);
    }

    /**
     * User can set complex bulk path ACL information
     */
    public function testCanSetComplexACLInformation()
    {
        $paths = [
            '/*/users/**',
            '/*/conversations/**' => [
                'methods' => ['GET']
            ]
        ];

        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->setPaths($paths);
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertTrue($parsedToken->hasClaim('acl'));
        $acl = $parsedToken->getClaim('acl');

        $this->assertCount(2, (array) $acl->paths);
        $this->assertTrue($acl->paths->{$paths[0]} instanceof stdClass);

        $convoPath = '/*/conversations/**';
        $this->assertTrue($acl->paths->{$convoPath} instanceof stdClass);
        $this->assertTrue(is_array($acl->paths->{$convoPath}->methods));
    }

    /**
     * User can add individual ACL paths
     */
    public function testCanAddACLPath()
    {
        $path = '/*/users/**';

        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->addPath($path);
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertTrue($parsedToken->hasClaim('acl'));
        $acl = $parsedToken->getClaim('acl');

        $this->assertCount(1, (array) $acl->paths);
        $this->assertTrue($acl->paths->{$path} instanceof stdClass);
    }

    /**
     * User can add individual ACL path information with additional constraints
     */
    public function testCanAddACLPathWithOptions()
    {
        $path = '/';
        $options = [
            'methods' => ['GET']
        ];

        $generator = new TokenGenerator(
            'd70425f2-1599-4e4c-81c4-cffc66e49a12',
            file_get_contents(__DIR__ . '/resources/private.key')
        );
        $generator->addPath($path, $options);
        $token = $generator->generate();

        $parsedToken = (new Parser())->parse($token);
        $this->assertTrue($parsedToken->hasClaim('acl'));
        $acl = $parsedToken->getClaim('acl');

        $this->assertCount(1, (array) $acl->paths);
        $this->assertTrue($acl->paths->{$path} instanceof stdClass);
        $this->assertSame($options['methods'], $acl->paths->{$path}->methods);
    }
}
