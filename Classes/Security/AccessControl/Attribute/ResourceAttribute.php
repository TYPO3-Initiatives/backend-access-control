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

/**
 * @api
 */
class ResourceAttribute extends \TYPO3\CMS\Security\Attribute\ResourceAttribute
{
    /**
     * @var array
     */
    public $permissions;

    /**
     * Creates a backend resource attribute.
     *
     * @param string $identifier Resource identifier
     */
    public function __construct(string $identifier)
    {
        parent::__construct($identifier);

        $this->permissions = [];
    }
}