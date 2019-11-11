<?php
declare(strict_types = 1);

namespace TYPO3\CMS\Backend\Security\AccessControl\Policy\ExpressionLanguage;

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

use Symfony\Component\ExpressionLanguage\ExpressionFunction;
use Symfony\Component\ExpressionLanguage\ExpressionFunctionProviderInterface;

/**
 * @internal
 */
class ResourceFunctionsProvider implements ExpressionFunctionProviderInterface
{
    public function getFunctions()
    {
        return [
            $this->getHasPermissionFunction(),
        ];
    }

    protected function getHasPermissionFunction(): ExpressionFunction
    {
        return new ExpressionFunction(
            'hasPermission',
            function () {
                // Not implemented, we only use the evaluator
            },
            function ($variables, ...$arguments) {
                if (count($arguments) === 4) {
                    foreach ($variables['resource']->getPermissions() as $permission) {
                        if (
                            $permission->getPrincipal()->getNamespace() === $arguments[0]
                            && $permission->getResource() === $arguments[1]
                            && $permission->getAction() === $arguments[2]
                            && $permission->getState() === $arguments[3]
                        ) {
                            return true;
                        }
                    }
                }

                return false;
            }
        );
    }
}