<?php
declare(strict_types=1);

namespace Nexmo\JWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Nexmo\JWT\Exception\InvalidJTIException;
use Ramsey\Uuid\Uuid;
use RuntimeException;

class TokenGenerator
{
    /**
     * UUID of the application we are generating a UUID for
     * @var string
     */
    protected $applicationId;

    /**
     * Number of seconds to expire in, defaults to 15 minutes
     * @var int
     */
    protected $ttl = 900;

    /**
     * UUIDv4 ID for the JWT
     * @var string
     */
    protected $jti;

    /**
     * Unix Timestamp at which this token becomes valid
     * @var int
     */
    protected $nbf;

    /**
     * ACL Path information
     * @var array<string, \stdClass>
     */
    protected $paths = [];

    /**
     * Private key text used for signing
     * @var string
     */
    protected $privateKey;

    /**
     * Subject to use in the JWT
     * @var string
     */
    protected $subject;

    public function __construct(string $applicationId, string $privateKey)
    {
        $this->applicationId = $applicationId;
        $this->privateKey = $privateKey;
    }

    /**
     * @param array<string, array> $options
     */
    public function addPath(string $path, array $options = []) : self
    {
        $this->paths[$path] = (object) $options;
        return $this;
    }

    public static function factory(string $applicationId, string $privateKey, array $options = []) : string
    {
        $generator = new self($applicationId, $privateKey);

        if (array_key_exists('ttl', $options)) {
            $generator->setTTL($options['ttl']);
        }

        if (array_key_exists('jti', $options)) {
            $generator->setJTI($options['jti']);
        }

        if (array_key_exists('paths', $options)) {
            $generator->setPaths($options['paths']);
        }

        if (array_key_exists('not_before', $options)) {
            $generator->setNotBefore($options['not_before']);
        }

        if (array_key_exists('subject', $options)) {
            $generator->setSubject($options['subject']);
        }

        return $generator->generate();
    }

    public function generate() : string
    {
        $iat = time();
        $exp = $iat + $this->ttl;

        $builder = new Builder();
        $builder->setIssuedAt($iat)
            ->setExpiration($exp)
            ->identifiedBy($this->getJTI())
            ->set('application_id', $this->applicationId);

        if (!empty($this->getPaths())) {
            $builder->set('acl', ['paths' => $this->getPaths()]);
        }

        try {
            $builder->canOnlyBeUsedAfter($this->getNotBefore());
        } catch (RuntimeException $e) {
            // This is fine, NBF isn't required
        }

        try {
            $builder->set('subject', $this->getSubject());
        } catch (RuntimeException $e) {
            // This is fine, Subject isn't required
        }

        return (string) $builder->sign(new Sha256(), $this->privateKey)->getToken();
    }

    public function getJTI() : string
    {
        if (!isset($this->jti)) {
            $this->jti = Uuid::uuid4()->toString();
        }

        return $this->jti;
    }

    public function getNotBefore() : int
    {
        if (!isset($this->nbf)) {
            throw new RuntimeException('Not Before time has not been set');
        }

        return $this->nbf;
    }

    /**
     * @return array<string, \stdClass>
     */
    public function getPaths() : array
    {
        return $this->paths;
    }

    public function getSubject() : string
    {
        if (!isset($this->subject)) {
            throw new RuntimeException('Subject has not been set');
        }

        return $this->subject;
    }

    public function setTTL(int $seconds) : self
    {
        $this->ttl = $seconds;
        return $this;
    }

    public function setJTI(string $uuid) : self
    {
        if (!Uuid::isValid($uuid)) {
            throw new InvalidJTIException('JTI must be a UUIDv4 string');
        }

        $this->jti = $uuid;
        return $this;
    }

    public function setNotBefore(int $timestamp) : self
    {
        $this->nbf = $timestamp;
        return $this;
    }

    /**
     * Sets the ACL path information for this token
     * WARNING: This will reset the paths to the new list, overriding any
     * existing paths.
     *
     * @param array<string|int, array|string> $pathData
     */
    public function setPaths(array $pathData) : self
    {
        $this->paths = [];
        foreach ($pathData as $key => $data) {
            if (is_string($key)) {
                $this->addPath($key, $data);
            } else {
                $this->addPath($data);
            }
        }

        return $this;
    }

    public function setSubject(string $subject) : self
    {
        $this->subject = $subject;
        return $this;
    }

    public function getTTL() : int
    {
        return $this->ttl;
    }
}
