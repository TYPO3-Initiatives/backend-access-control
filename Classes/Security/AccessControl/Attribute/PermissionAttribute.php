<?php
declare(strict_types = 1);

namespace TYPO3\CMS\Backend\Security\AccessControl\Attribute;

/*
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

use TYPO3\AccessControl\Attribute\AbstractAttribute;
use TYPO3\AccessControl\Attribute\PrincipalAttribute;

/**
 * @api
 */
final class PermissionAttribute extends AbstractAttribute
{
    /**
     * @var string
     */
    const STATE_PERMIT = 'permit';

    /**
     * @var string
     */
    const STATE_DENY = 'deny';

    /**
     * Creates a backend permission attribute.
     *
     * @param PrincipalAttribute $principal Principal
     * @param string $state Resource identifier
     * @param string $action Action identifier
     * @param string $state State identifier
     */
    public function __construct(PrincipalAttribute $principal, string $resource, string $action, string $state)
    {
        $this->meta['action'] = $action;
        $this->meta['principal'] = $principal;
        $this->meta['resource'] = $resource;
        $this->meta['state'] = $state;
    }

    public function getAction(): string
    {
        return $this->meta['action'];
    }

    public function getResource(): string
    {
        return $this->meta['resource'];
    }

    public function getState(): string
    {
        return $this->meta['state'];
    }

    public function getPrincipal(): PrincipalAttribute
    {
        return $this->meta['principal'];
    }
}