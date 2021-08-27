<?php

namespace CasbinAdapter\LaminasDb\Tests;

use Casbin\Enforcer;
use CasbinAdapter\LaminasDb\Adapter;
use PHPUnit\Framework\TestCase;
use Laminas\Db\TableGateway\TableGateway;
use Laminas\Db\Adapter\Adapter as LaminasDbAdapter;
use Laminas\Db\Sql\Ddl\DropTable;
use Laminas\Db\Sql\Ddl\CreateTable;
use Laminas\Db\Sql\Ddl\Column\Varchar;
use Laminas\Db\Sql\Sql;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;
use Laminas\Db\Sql\Select;

class AdapterTest extends TestCase
{
    protected $config = [];

    protected $tableName = 'casbin_rule';

    public $initialized = false;

    protected function initConfig()
    {
        $this->config = [
            'driver' => 'Pdo_Mysql', // Mysqli, Sqlsrv, Pdo_Sqlite, Pdo_Mysql, Pdo(= Other PDO Driver)
            'hostname' => $this->env('DB_HOST', '127.0.0.1'),
            'database' => $this->env('DB_DATABASE', 'casbin'),
            'username' => $this->env('DB_USERNAME', 'root'),
            'password' => $this->env('DB_PASSWORD', ''),
            'port' => $this->env('DB_PORT', 3306),
        ];
    }

    protected function initialize()
    {
        if ($this->initialized) {
            return;
        }

        $this->initConfig();

        $laminasDbAdapter = new LaminasDbAdapter($this->config);
        $tableGateway = new TableGateway($this->tableName, $laminasDbAdapter);

        $ddl = new DropTable($this->tableName);
        // Existence of $adapter is assumed.
        $sql = new Sql($laminasDbAdapter);

        try {
            $laminasDbAdapter->query(
                $sql->buildSqlString($ddl),
                $laminasDbAdapter::QUERY_MODE_EXECUTE
            );
        } catch (\Exception $e) {
        }

        $table = new CreateTable($this->tableName);
        $table->addColumn(new Varchar('ptype', 255));
        $table->addColumn(new Varchar('v0', 255, true));
        $table->addColumn(new Varchar('v1', 255, true));
        $table->addColumn(new Varchar('v2', 255, true));
        $table->addColumn(new Varchar('v3', 255, true));
        $table->addColumn(new Varchar('v4', 255, true));
        $table->addColumn(new Varchar('v5', 255, true));

        $laminasDbAdapter->query(
            $sql->buildSqlString($table),
            $laminasDbAdapter::QUERY_MODE_EXECUTE
        );
        $tableGateway->delete('1 = 1');

        $tableGateway->insert(['ptype' => 'p', 'v0' => 'alice', 'v1' => 'data1', 'v2' => 'read']);
        $tableGateway->insert(['ptype' => 'p', 'v0' => 'bob', 'v1' => 'data2', 'v2' => 'write']);
        $tableGateway->insert(['ptype' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'read']);
        $tableGateway->insert(['ptype' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'write']);
        $tableGateway->insert(['ptype' => 'g', 'v0' => 'alice', 'v1' => 'data2_admin']);
    }

    protected function getEnforcer($adapter = null)
    {
        $this->initialize();

        if (!$adapter) {
            $adapter = Adapter::newAdapter($this->config);
        }

        return new Enforcer(__DIR__.'/rbac_model.conf', $adapter);
    }

    public function testLoadPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testLoadPolicyForGivenTableGateway()
    {
        $this->initialize();
        $e = $this->getEnforcer(
            Adapter::newAdapter(
                new TableGateway(
                    $this->tableName,
                    new LaminasDbAdapter($this->config)
                )
            )
        );

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testLoadPolicyForGivenLaminasDbAdapter()
    {
        $this->initialize();

        $e = $this->getEnforcer(
            Adapter::newAdapter(
                new LaminasDbAdapter($this->config)
            )
        );

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testAddPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));
        $e->addPermissionForUser('eve', 'data3', 'read');
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
    }

    public function testAddPolicies()
    {
        $policies = [
            ['u1', 'd1', 'read'],
            ['u2', 'd2', 'read'],
            ['u3', 'd3', 'read'],
        ];
        $e = $this->getEnforcer();
        $e->clearPolicy();
        $this->assertEquals([], $e->getPolicy());
        $e->addPolicies($policies);
        $this->assertEquals($policies, $e->getPolicy());
    }

    public function testSavePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data4', 'read'));
        $model = $e->getModel();
        $model->clearPolicy();
        $model->addPolicy('p', 'p', ['alice', 'data4', 'read']);
        $adapter = $e->getAdapter();
        $adapter->savePolicy($model);
        $this->assertTrue($e->enforce('alice', 'data4', 'read'));
    }

    public function testRemovePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $e->addPermissionForUser('alice', 'data5', 'read');
        $this->assertTrue($e->enforce('alice', 'data5', 'read'));
        $e->deletePermissionForUser('alice', 'data5', 'read');
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
    }

    public function testRemovePolicies()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $e->removePolicies([
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ]);

        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write']
        ], $e->getPolicy());
    }

    public function testRemoveFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->removeFilteredPolicy(1, 'data1');
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
        $e->removeFilteredPolicy(1, 'data2', 'read');
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
        $e->removeFilteredPolicy(2, 'write');
        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
    }

    public function testLoadFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $e->clearPolicy();
        $adapter = $e->getAdapter();
        $adapter->setFiltered(true);
        $this->assertEquals([], $e->getPolicy());
        
        // invalid filter type
        try {
            $filter = ['alice', 'data1', 'read'];
            $e->loadFilteredPolicy($filter);
            $exception = InvalidFilterTypeException::class;
            $this->fail("Expected exception $exception not thrown");
        } catch (InvalidFilterTypeException $exception) {
            $this->assertEquals("invalid filter type", $exception->getMessage());
        }

        // string
        $filter = "v0 = 'bob'";
        $e->loadFilteredPolicy($filter);
        $this->assertEquals([
            ['bob', 'data2', 'write']
        ], $e->getPolicy());
        
        // Filter
        $filter = new Filter(['v2'], ['read']);
        $e->loadFilteredPolicy($filter);
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['data2_admin', 'data2', 'read'],
        ], $e->getPolicy());

        // Closure
        $e->loadFilteredPolicy(function (Select $select) {
            return $select->where(['v1' => 'data1']);
        });

        $this->assertEquals([
            ['alice', 'data1', 'read'],
        ], $e->getPolicy());
    }

    public function testUpdatePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $e->updatePolicy(
            ['alice', 'data1', 'read'],
            ['alice', 'data1', 'write']
        );

        $e->updatePolicy(
            ['bob', 'data2', 'write'],
            ['bob', 'data2', 'read']
        );

        $this->assertEquals([
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());
    }

    public function testUpdatePolicies()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $oldPolicies = [
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write']
        ];
        $newPolicies = [
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read']
        ];

        $e->updatePolicies($oldPolicies, $newPolicies);

        $this->assertEquals([
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());
    }

    protected function env($key, $default = null)
    {
        $value = getenv($key);
        if (is_null($default)) {
            return $value;
        }

        return false === $value ? $default : $value;
    }
}
