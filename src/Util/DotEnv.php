<?php

namespace App\Util;

use App\Exceptions\DotEnvException;
use Symfony\Component\Dotenv\Dotenv as DotEnvBundle;

class DotEnv
{
    const DEFAULT_ENV = __DIR__.'/../../.env';
    const LOCAL_ENV = __DIR__.'/../../.env.local';

    /**
     * @return string
     * @throws DotEnvException
     */
    public function load(string $parameter): string
    {
        $env = self::LOCAL_ENV;
        if (false === file_exists($env)) {
            $env = self::DEFAULT_ENV;
        }

        $dotenv = new DotEnvBundle();
        $dotenv->loadEnv($env);

        if (false === array_key_exists($parameter, $_ENV) && self::DEFAULT_ENV == $env) {
            throw new DotEnvException(sprintf('missing parameter `%s` in `%s` file.', $parameter, $env));
        }

        if (false === array_key_exists($parameter, $_ENV) && self::LOCAL_ENV == $env) {
            $env = self::DEFAULT_ENV;
            $dotenv->loadEnv($env);
            if (false === array_key_exists($parameter, $_ENV)) {
                throw new DotEnvException(sprintf('missing parameter `%s` in `%s` file.', $parameter, $env));
            }
        }

        return $_ENV[$parameter];
    }
}