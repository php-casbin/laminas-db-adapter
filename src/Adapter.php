<?php

namespace CasbinAdapter\LaminasDb;

use Casbin\Persist\Adapter as AdapterContract;
use Casbin\Persist\BatchAdapter as BatchAdapterContract;
use Casbin\Persist\FilteredAdapter as FilteredAdapterContract;
use Casbin\Persist\AdapterHelper;
use Laminas\Db\Adapter\AdapterInterface as LaminasDbAdapterInterface;
use Laminas\Db\Adapter\Adapter as LaminasDbAdapter;
use Laminas\Db\TableGateway\TableGateway;
use Laminas\Db\TableGateway\TableGatewayInterface;
use Laminas\Db\Sql\Select;
use Casbin\Model\Model;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;

/**
 * Laminas DB Adapter for Casbin.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract, BatchAdapterContract, FilteredAdapterContract
{
    use AdapterHelper;

    /**
     * @var bool
     */
    private $filtered = false;

    /**
     * @var TableGatewayInterface
     */
    protected $tableGateway;

    /**
     * @var LaminasDbAdapterInterface
     */
    protected $dbAdapter;

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
    public function loadPolicy($model): void
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
    public function savePolicy($model): void
    {
        foreach ($model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        foreach ($model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }
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
    public function addPolicy($sec, $ptype, $rule): void
    {
        $this->savePolicyLine($ptype, $rule);
    }

    /**
     * Adds a policy rules to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     */
    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        $columns = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $values = [];
        $sets = [];
        $columnsCount = count($columns);
        foreach ($rules as $rule) {
            array_unshift($rule, $ptype);
            $values = array_merge($values, array_pad($rule, $columnsCount, null));
            $sets[] = array_pad([], $columnsCount, '?');
        }
        $valuesStr = implode(', ', array_map(function ($set) {
            return '(' . implode(', ', $set) . ')';
        }, $sets));
        $sql = 'INSERT INTO ' . $this->casbinRuleTableName . ' (' . implode(', ', $columns) . ')' . ' VALUES' . $valuesStr;
        
        $driver = $this->tableGateway->adapter->getDriver();
        $statement = $driver->createStatement($sql);
        $result = $statement->execute($values);
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     */
    public function removePolicy($sec, $ptype, $rule): void
    {
        $where['ptype'] = $ptype;
        foreach ($rule as $key => $value) {
            $where['v'.strval($key)] = $value;
        }

        $this->tableGateway->delete($where);
    }

    /**
     * Removes policy rules from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     */
    public function removePolicies(string $sec, string $ptype, array $rules): void
    {
        $this->tableGateway->adapter->getDriver()->getConnection()->beginTransaction(function () use ($sec, $ptype, $rules) {
            foreach ($rules as $rule) {
                $this->removePolicy($sec, $ptype, $rule);
            }
        });
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
    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues): void
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

    /**
     * Loads only policy rules that match the filter.
     *
     * @param Model $model
     * @param mixed $filter
     */
    public function loadFilteredPolicy(Model $model, $filter): void
    {
        if (is_string($filter)) {
            $where = $filter;
        } elseif ($filter instanceof Filter) {
            foreach ($filter->p as $k => $v) {
                $where[$v] = $filter->g[$k];
            }
        } elseif ($filter instanceof \Closure) {
            $where = $filter;
        } else {
            throw new InvalidFilterTypeException('invalid filter type');
        }
        $rows = $this->tableGateway->select($where)->toArray();

        foreach ($rows as $row) {
            $row = array_filter($row, function ($value) {
                return !is_null($value) && $value !== '';
            });
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }
        $this->setFiltered(true);
    }

    /**
     * Returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered(): bool
    {
        return $this->filtered;
    }

    /**
     * Sets filtered parameter.
     *
     * @param bool $filtered
     */
    public function setFiltered(bool $filtered): void
    {
        $this->filtered = $filtered;
    }
}
