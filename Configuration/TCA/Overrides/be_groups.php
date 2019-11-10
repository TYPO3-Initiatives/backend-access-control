<?php
defined('TYPO3_MODE') or die();

call_user_func(function () {

    $additionalColumns = [
        'permissions' => [
            'exclude' => true,
            'label' => 'Advanced Permissions',
            'config' => [
                'type' => 'text',
                'rows' => 5,
                'cols' => 30,
                'max' => 2000,
            ],
        ],
    ];

    \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addTCAcolumns('be_groups', $additionalColumns);
    \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addToAllTCAtypes('be_groups', 'permissions', '', 'after:allowed_languages');
});