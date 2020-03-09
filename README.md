# Laminas-db Adapter for PHP-Casbin

[![Build Status](https://travis-ci.org/php-casbin/laminas-db-adapter.svg?branch=master)](https://travis-ci.org/php-casbin/laminas-db-adapter)
[![Coverage Status](https://coveralls.io/repos/github/php-casbin/laminas-db-adapter/badge.svg)](https://coveralls.io/github/php-casbin/laminas-db-adapter)
[![Latest Stable Version](https://poser.pugx.org/casbin/laminas-db-adapter/v/stable)](https://packagist.org/packages/casbin/laminas-db-adapter)
[![Total Downloads](https://poser.pugx.org/casbin/laminas-db-adapter/downloads)](https://packagist.org/packages/casbin/laminas-db-adapter)
[![License](https://poser.pugx.org/casbin/laminas-db-adapter/license)](https://packagist.org/packages/casbin/laminas-db-adapter)

[Laminas-db](https://github.com/laminas/laminas-db) adapter for [PHP-Casbin](https://github.com/php-casbin/php-casbin).

The list of officially supported drivers:

- `IbmDb2`: The ext/ibm_db2 driver
- `Mysqli`: The ext/mysqli driver
- `Oci8`: The ext/oci8 driver
- `Pgsql`: The ext/pgsql driver
- `Sqlsrv`: The ext/sqlsrv driver (from Microsoft)
- `Pdo_Mysql`: MySQL via the PDO extension
- `Pdo_Sqlite`: SQLite via the PDO extension
- `Pdo_Pgsql`: PostgreSQL via the PDO extension

### Installation

Use [Composer](https://getcomposer.org/).

```
composer require casbin/laminas-db-adapter
```

### Usage

Before using it, you need to create a table named `casbin_rule` for Casbin to store the policy.

Take mysql as an example:

```sql
CREATE TABLE `casbin_rule` (
  `ptype` varchar(255) NOT NULL,
  `v0` varchar(255) DEFAULT NULL,
  `v1` varchar(255) DEFAULT NULL,
  `v2` varchar(255) DEFAULT NULL,
  `v3` varchar(255) DEFAULT NULL,
  `v4` varchar(255) DEFAULT NULL,
  `v5` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Then you can start like this:

```php

require_once './vendor/autoload.php';

use Casbin\Enforcer;
use Casbin\Util\Log;
use CasbinAdapter\LaminasDb\Adapter;

$adapter = new Adapter([
	'driver' => 'Pdo_Mysql', // IbmDb2, Mysqli, Oci8, Pgsql, Sqlsrv, Pdo_Mysql, Pdo_Sqlite, Pdo_Pgsql
	'hostname' => '127.0.0.1',
	'database' => 'test',
	'username' => 'root',
	'password' => '',
	'port' => '3306',
]);

$e = new Enforcer('path/to/model.conf', $adapter);

$sub = "alice"; // the user that wants to access a resource.
$obj = "data1"; // the resource that is going to be accessed.
$act = "read"; // the operation that the user performs on the resource.

if ($e->enforce($sub, $obj, $act) === true) {
    // permit alice to read data1
} else {
    // deny the request, show an error
}
```

### Getting Help

- [php-casbin](https://github.com/php-casbin/php-casbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
