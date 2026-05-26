"""Declarative base."""
from sqlalchemy import Column, String, Table; from sqlalchemy.orm import DeclarativeBase
class Base(DeclarativeBase): pass
tenant_stub = Table("tenant", Base.metadata, Column("id", String(30), primary_key=True), schema="tenant")
