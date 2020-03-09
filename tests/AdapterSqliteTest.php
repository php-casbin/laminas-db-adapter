<?php

namespace CasbinAdapter\LaminasDb\Tests;

class AdapterSqliteTest extends AdapterTest
{
    protected function initConfig()
    {
        $this->config = [
            'driver' => 'Pdo_Sqlite',
            'database' => __DIR__.'/'.$this->env('DB_DATABASE', 'casbin').'.db',
        ];
    }
}
