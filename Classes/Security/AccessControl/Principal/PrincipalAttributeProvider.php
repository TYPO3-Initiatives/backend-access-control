<?php
declare(strict_types = 1);

namespace TYPO3\CMS\Backend\Security\AccessControl\Principal;

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

use TYPO3\CMS\Backend\Security\AccessControl\Attribute\GroupAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\RoleAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\UserAttribute;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Security\AccessControl\Event\SubjectRetrivalEvent;

/**
 * @internal
 * @todo Fetch system maintainer role using context.
 */
class PrincipalAttributeProvider
{
    /**
     * @var FrontendInterface
     */
    private $cache;

    public function __construct(FrontendInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * @inheritdoc
     */
    public function __invoke(SubjectRetrivalEvent $event): void
    {
        if (!$event->getContext()->getAspect('backend.user')->get('isLoggedIn')) {
            return;
        }

        $userAspect = $event->getContext()->getAspect('backend.user');
        $cacheIdentifier = sha1(static::class . '_user_' . $userAspect->get('id'));
        $principalAttributes = $this->cache->get($cacheIdentifier);

        if ($principalAttributes === false) {
            $principalAttributes = [];

            $principalAttributes[] = new UserAttribute((string) $userAspect->get('id'));
    
            foreach ($userAspect->get('groupIds') as $groupId) {
                $principalAttributes[] = new GroupAttribute((string) $groupId);
            }
    
            if ($userAspect->get('isAdmin')) {
                $principalAttributes[] = new RoleAttribute('administrator');
            }

            /*if ($userAspect->get('isSystemMaintainer')) {
                $subject->principals[] = new RolePrincipalAttribute('system-maintainer');
            }*/
            
            $this->cache->set($cacheIdentifier, $principalAttributes);
        }

        foreach ($principalAttributes as $principalAttribute) {
            $event->addPrincipal($principalAttribute);
        }
    }
}