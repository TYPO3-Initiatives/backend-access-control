<?php
declare(strict_types = 1);

namespace TYPO3\CMS\Backend\Security\AccessControl\Permission;

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
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\PermissionAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\ResourceAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Attribute\UserAttribute;
use TYPO3\CMS\Backend\Security\AccessControl\Permission\PermissionConfigurationLoader;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\AccessControl\Event\AttributeRetrievalEvent;
use TYPO3\AccessControl\Utility\PrincipalUtility;

/**
 * @internal
 */
class PermissionAttributeProvider
{
    /**
     * @var FrontendInterface
     */
    private $cache;

    /**
     * @var array
     */
    private $permissionsConfiguration;

    public function __construct(FrontendInterface $cache)
    {
        $permissionConfigurationLoader = GeneralUtility::makeInstance(PermissionConfigurationLoader::class);

        $this->cache = $cache;
        $this->permissionsConfiguration = $permissionConfigurationLoader->getPermissionConfiguration();
    }

    /**
     * @inheritdoc
     */
    public function __invoke(AttributeRetrievalEvent $event): void
    {
        if (!$event->getAttribute() instanceof ResourceAttribute) {
            return;
        }

        $userAttributes = PrincipalUtility::filterList(
            $event->getSubject()->getPrincipals(), 
            static function ($principal) {
                return $principal instanceof UserAttribute;
            }
        );

        $groupAttributes = PrincipalUtility::filterList(
            $event->getSubject()->getPrincipals(), 
            static function ($principal) {
                return $principal instanceof GroupAttribute;
            }
        );

        if (count($userAttributes) === 0 && count($groupAttributes) === 0) {
            return;
        }

        ksort($userAttributes);
        ksort($groupAttributes);

        $cacheIdentifier = sha1(
            static::class . '_permissions_'
            . implode('_', array_keys($userAttributes))
            . implode('_', array_keys($groupAttributes))
        );

        $resourceAttribute = $event->getAttribute();
        $permissionAttributes = $this->cache->get($cacheIdentifier);

        if ($permissionAttributes === false) {
            $resourceNamespaces = array_merge(
                $this->permissionsConfiguration[$resourceAttribute->getNamespace()]['dependencies'] ?? [],
                [$resourceAttribute->getNamespace()]
            );
            $permissionAttributes = [];

            foreach ($resourceNamespaces as $resourceNamespace) {
                foreach ($userAttributes as $userAttribute) {
                    foreach ($this->getUserPermissions($userAttribute->getIdentifier(), $resourceNamespace) as $permission) {
                        $permissionAttributes[] = new PermissionAttribute(
                            $userAttribute,
                            $resourceNamespace,
                            $permission['action'],
                            $permission['state']
                        );
                    }
                }
                foreach ($groupAttributes as $groupAttribute) {
                    foreach ($this->getGroupPermissions($groupAttribute->getIdentifier(), $resourceNamespace) as $permission) {
                        $permissionAttributes[] = new PermissionAttribute(
                            $groupAttribute,
                            $resourceNamespace,
                            $permission['action'],
                            $permission['state']
                        );
                    }
                }
            }

            $this->cache->set($cacheIdentifier, $permissionAttributes);
        }

        foreach ($permissionAttributes as $permissionAttribute) {
            $resourceAttribute->addPermission($permissionAttribute);
        }
    }

    protected function getGroupPermissions(string $groupIdentifier, string $resource): array
    {
        $cacheIdentifier = sha1(static::class . '_group_permissions');

        if (($entry = $this->cache->get($cacheIdentifier)) === false) {
            $entry = [];
            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('be_groups');
            $expressionBuilder = $queryBuilder->expr();
            $ressource = $queryBuilder->select(
                    'uid',
                    'permissions'
                )
                ->from('be_groups')
                ->where($expressionBuilder->andX(
                    $expressionBuilder->eq(
                        'pid',
                        $queryBuilder->createNamedParameter(0, \PDO::PARAM_INT)
                    ),
                    $expressionBuilder->orX(
                        $expressionBuilder->eq('lockToDomain', $queryBuilder->quote('')),
                        $expressionBuilder->isNull('lockToDomain'),
                        $expressionBuilder->eq(
                            'lockToDomain',
                            $queryBuilder->createNamedParameter(GeneralUtility::getIndpEnv('HTTP_HOST'), \PDO::PARAM_STR)
                        )
                    )
                ))
                ->execute();

            while ($row = $ressource->fetch(\PDO::FETCH_ASSOC)) {
                $entry[$row['uid']] = json_decode((string) $row['permissions'], true);
            }

            $this->cache->set($cacheIdentifier, $entry);
        }

        return $entry[$groupIdentifier][$resource] ?? [];
    }

    protected function getUserPermissions(string $userIdentifier, string $resource): array
    {
        $cacheIdentifier = sha1(static::class . '_user_permissions');

        if (($entry = $this->cache->get($cacheIdentifier)) === false) {
            $cacheEntry = [];
            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('be_users');
            $expressionBuilder = $queryBuilder->expr();
            $ressource = $queryBuilder->select(
                    'uid',
                    'permissions'
                )
                ->from('be_users')
                ->where($expressionBuilder->eq(
                    'pid',
                    $queryBuilder->createNamedParameter(0, \PDO::PARAM_INT)
                ))
                ->execute();

            while ($row = $ressource->fetch(\PDO::FETCH_ASSOC)) {
                $entry[$row['uid']] = json_decode((string) $row['permissions'], true);
            }

            $this->cache->set($cacheIdentifier, $entry);
        }

        return $entry[$userIdentifier][$resource] ?? [];
    }
}
