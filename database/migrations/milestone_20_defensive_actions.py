"""Reversible migration for the Milestone 20 defensive-action ledger."""
from database.models.defensive_action import DefensiveAction


def upgrade(engine):
    DefensiveAction.__table__.create(bind=engine, checkfirst=True)


def downgrade(engine):
    DefensiveAction.__table__.drop(bind=engine, checkfirst=True)
