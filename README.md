# Backend Access Control

This extension provides a basic security model for the TYPO3 CMS backend based on the [TYPO3 CMS security framework](https://github.com/typo3-initiatives/security).

*This implementation is a proof-of-concept prototype and thus experimental development. Since not all planned features are implemented, this extension should not be used for production sites.*

## Installation

Use composer to install this extension in your project:

```bash
composer config repositories.security git https://github.com/typo3-initiatives/backend-access-control
composer require typo3/cms-backend-access-control
```

## Permissions

Each *permission* has a *resource*, a *principal*, an *action* and a *state*. A *principal* within the backend is either an user or a group. The *state* of a *permission* specify whether the entry should have access (`permit`) or not have access (`deny`). An *permission* is *explicit* when its *principal* is a current user. A *permission* is *implicit* when its principal is a current group.

A permission attribute provider is responsible to collect all relevant permissions for an access request. Therefore the following rules MUST be applied:

* Groups inherit all rights of their subgroups.
* Users inherit all rights of their groups.

Policies are responsible for evaluating permissions during an access request. They MUST consider the following rules:

* Explicit permissions take precedence over the implicit permissions.
* Access restrictions have priority over implicit permissions.
* Access restrictions have priority over explicit permissions.

They also SHOULD consider the following rule:

* Resources can inherit permissions from other resources.

## Development

Development for this extension is happening as part of the [TYPO3 persistence initiative](https://typo3.org/community/teams/typo3-development/initiatives/persistence/).
