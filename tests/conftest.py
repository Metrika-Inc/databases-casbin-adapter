import os

import sqlalchemy
from casbin import Enforcer
from databases import Database
from pytest import fixture
from sqlalchemy import Table, Column, String
from sqlalchemy.sql.ddl import CreateTable

from casbin_databases_adapter import DatabasesAdapter


@fixture(scope="session")
async def db() -> Database:
    db = Database("sqlite://", force_rollback=True)
    await db.connect()
    yield db
    await db.disconnect()


@fixture(scope="session")
async def casbin_rule_table(db: Database):
    metadata = sqlalchemy.MetaData()
    table = Table(
        "casbin_rules",
        metadata,
        Column("id", String(64), primary_key=True),
        Column("ptype", String(255)),
        Column("v0", String(255)),
        Column("v1", String(255)),
        Column("v2", String(255)),
        Column("v3", String(255)),
        Column("v4", String(255)),
        Column("v5", String(255)),
    )
    q = CreateTable(table)
    await db.execute(query=str(q))
    return table


@fixture(scope="function")
async def setup_policies(db: Database, casbin_rule_table: Table):
    rows = [
        DatabasesAdapter._policy_to_dict("p", ["alice", "data1", "read"]),
        DatabasesAdapter._policy_to_dict("p", ["bob", "data2", "write"]),
        DatabasesAdapter._policy_to_dict("p", ["data2_admin", "data2", "read"]),
        DatabasesAdapter._policy_to_dict("p", ["data2_admin", "data2", "write"]),
        DatabasesAdapter._policy_to_dict("g", ["alice", "data2_admin"]),
    ]
    await db.execute_many(casbin_rule_table.insert(), values=rows)
    yield await db.fetch_all(casbin_rule_table.select())
    await db.execute(casbin_rule_table.delete())


@fixture(scope="function")
def model_conf_path():
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + "rbac_model.conf")


@fixture(scope="function")
async def enforcer(
    db: Database, setup_policies, casbin_rule_table: Table, model_conf_path
) -> Enforcer:
    adapter = DatabasesAdapter(db, table=casbin_rule_table)
    enforcer = Enforcer(model_conf_path, adapter)
    await enforcer.load_policy()
    return enforcer
