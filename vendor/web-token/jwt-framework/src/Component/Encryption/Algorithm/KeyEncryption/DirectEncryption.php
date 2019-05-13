<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

/**
 * Interface DirectEncryption.
 */
interface DirectEncryption extends KeyEncryptionAlgorithm
{
    /**
     * @param \Jose\Component\Core\JWK $key The key used to get the CEK
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The CEK
     */
    public function getCEK(JWK $key): string;
}