<?php

namespace CasbinAdapter\LaminasDb;

use Casbin\Persist\Adapter as AdapterContract;
use Casbin\Persist\AdapterHelper;
use Laminas\Db\Adapter\AdapterInterface as LaminasDbAdapterInterface;
use Laminas\Db\Adapter\Adapter as LaminasDbAdapter;
use Laminas\Db\TableGateway\TableGateway;
use Laminas\Db\TableGateway\TableGatewayInterface;
use Laminas\Db\Sql\Select;

/**
 * Laminas DB Adapter for Casbin.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract
{
    use AdapterHelper;

    /**
     * @var TableGatewayInterface
     */
    protected $tableGateway;

    /**
     * default table name.
     *
     * @var string
     */
    public $casbinRuleTableName = 'casbin_rule';

    /**
     * the Adapter constructor.
     *
     * @param TableGatewayInterface|LaminasDbAdapterInterface|array $config
     */
    public function __construct($config)
    {
        if ($config instanceof TableGatewayInterface) {
            $this->tableGateway = $config;
        } else {
            if ($config instanceof LaminasDbAdapterInterface) {
                $dbAdapter = $config;
            } else {
                $dbAdapter = new LaminasDbAdapter($config);
            }

            $this->tableGateway = new TableGateway($this->casbinRuleTableName, $dbAdapter);
        }
    }

    /**
     * Initialize a new Adapter.
     *
     * @param TableGatewayInterface|LaminasDbAdapterInterface|array $config
     */
    public static function newAdapter($config)
    {
        return new static($config);
    }

    /**
     * gets TableGateway.
     *
     * @return TableGatewayInterface
     */
    public function getTableGateway()
    {
        return $this->tableGateway;
    }

    /**
     * savePolicyLine function.
     *
     * @param string $ptype
     * @param array  $rule
     */
    public function savePolicyLine($ptype, array $rule)
    {
        $col['ptype'] = $ptype;
        foreach ($rule as $key => $value) {
            $col['v'.strval($key).''] = $value;
        }

        $this->tableGateway->insert($col);
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param Model $model
     */
    public function loadPolicy($model)
    {
        $rows = $this->tableGateway->select(function (Select $select) {
            $select->columns(['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5']);
        })->toArray();

        foreach ($rows as $row) {
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param Model $model
     *
     * @return bool
     */
    public function savePolicy($model)
    {
        foreach ($model->model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        foreach ($model->model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        return true;
    }

    /**
     * Adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return mixed
     */
    public function addPolicy($sec, $ptype, $rule)
    {
        return $this->savePolicyLine($ptype, $rule);
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     */
    public function removePolicy($sec, $ptype, $rule)
    {
        $where['ptype'] = $ptype;
        foreach ($rule as $key => $value) {
            $where['v'.strval($key)] = $value;
        }

        $this->tableGateway->delete($where);
    }

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param mixed  ...$fieldValues
     */
    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {
        $where['ptype'] = $ptype;
        foreach (range(0, 5) as $value) {
            if ($fieldIndex <= $value && $value < $fieldIndex + count($fieldValues)) {
                if ('' != $fieldValues[$value - $fieldIndex]) {
                    $where['v'.strval($value)] = $fieldValues[$value - $fieldIndex];
                }
            }
        }

        $this->tableGateway->delete($where);
    }
}
