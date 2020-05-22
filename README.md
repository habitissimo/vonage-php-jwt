Client Library for PHP 
============================
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
[![Build Status](https://api.travis-ci.org/Nexmo/nexmo-jwt-php.svg?branch=master)](https://travis-ci.org/Nexmo/nexmo-jwt-php)
[![Latest Stable Version](https://poser.pugx.org/nexmo/jwt/v/stable)](https://packagist.org/packages/nexmo/jwt)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.txt)
[![codecov](https://codecov.io/gh/Nexmo/nexmo-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/Nexmo/nexmo-jwt)

<img src="https://developer.nexmo.com/assets/images/Vonage_Nexmo.svg" height="48px" alt="Nexmo is now known as Vonage" />

*This library requires a minimum PHP version of 7.1*

This is the PHP library for generating JWTS to use Nexmo's API. To use this, you'll need a Nexmo account. Sign up [for free at 
nexmo.com][signup].

 * [Installation](#installation)
 * [Usage](#usage)
 * [Examples](#examples)
 * [Contributing](#contributing) 

Installation
------------

To use the client library you'll need to have [created a Nexmo account][signup]. 

To install the PHP client library to your project, we recommend using [Composer](https://getcomposer.org/).

```bash
composer require nexmo/jwt
```

> You don't need to clone this repository to use this library in your own projects. Use Composer to install it from Packagist.

If you're new to Composer, here are some resources that you may find useful:

* [Composer's Getting Started page](https://getcomposer.org/doc/00-intro.md) from Composer project's documentation.
* [A Beginner's Guide to Composer](https://scotch.io/tutorials/a-beginners-guide-to-composer) from the good people at ScotchBox.

Usage
-----

If you're using Composer, make sure the autoloader is included in your project's bootstrap file:

```php
require_once "vendor/autoload.php";
```

Create a Token Generator with the Application ID and Private Key of the Nexmo Application you want to access:

```php
$generator = new Nexmo\JWT\TokenGenerator('d70425f2-1599-4e4c-81c4-cffc66e49a12', file_get_contents('/path/to/private.key'));
```

You can then retrieve a generated JWT token by calling the `generate()` method on the Token Generator:

```php
$token = $generator->generate();
```

This will return a string token that can be used for Bearer Authentication to Nexmo APIs that require JWTs.

Examples
--------

### Generating a token with a specific expiration time

By default, Nexmo JWT tokens are generated with a 15 minute expiration. In cases where the token lifetime should be different,
you can override this setting by calling the `setExpirationTime()` on the Token Generator and passing the length of the expiration,
in seconds.

```php
$generator->setExpirationTime(30 * 60); // Set expiration to 30 minutes after token creation
```

### Setting ACLs

Nexmo JWTs will default to full access to all of the paths for an application, but this may not be desirable for cases where clients
may need restricted access. You can specify the paths that a JWT token is valid for by using the `setPaths()` or `addPath()` methods
to set the path information in bulk, or add individual paths in a more fluent interface.

```php
// Set paths in bulk
$generator->setPaths([
    '/*/users/**',
    '/*/conversations/**'
]);

// Set paths individually
$generator->addPath('/*/users/**');
$generator->addPath('/*/conversations/**');
```

For more information on assigning ACL information, please see [How to generate JWTs
 on the Nexmo Developer Platform](https://developer.nexmo.com/conversation/guides/jwt-acl)

Contributing
------------

This library is actively developed and we love to hear from you! Please feel free to [create an issue][issues] or [open a pull request][pulls] with your questions, comments, suggestions and feedback.

[signup]: https://dashboard.nexmo.com/sign-up?utm_source=DEV_REL&utm_medium=github&utm_campaign=php-client-library
[license]: LICENSE.txt
[issues]: https://github.com/Nexmo/nexmo-jwt-php/issues
[pulls]: https://github.com/Nexmo/nexmo-jwt-php/pulls

