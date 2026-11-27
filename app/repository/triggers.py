 
BLOCKS_NO_UPDATE = "blocks_no_update"
BLOCKS_NO_DELETE = "blocks_no_delete"
AUDIT_NO_UPDATE = "audit_events_no_update"
AUDIT_NO_DELETE = "audit_events_no_delete"
VERIFICATIONS_NO_UPDATE = "verification_results_no_update"
VERIFICATIONS_NO_DELETE = "verification_results_no_delete"

ALL_TRIGGERS = (
    BLOCKS_NO_UPDATE, BLOCKS_NO_DELETE,
    AUDIT_NO_UPDATE, AUDIT_NO_DELETE,
    VERIFICATIONS_NO_UPDATE, VERIFICATIONS_NO_DELETE,
)

_TRIGGER_TABLE = (
    (BLOCKS_NO_UPDATE, "UPDATE", "blocks"),
    (BLOCKS_NO_DELETE, "DELETE", "blocks"),
    (AUDIT_NO_UPDATE, "UPDATE", "audit_events"),
    (AUDIT_NO_DELETE, "DELETE", "audit_events"),
    (VERIFICATIONS_NO_UPDATE, "UPDATE", "verification_results"),
    (VERIFICATIONS_NO_DELETE, "DELETE", "verification_results"),
)


def create_triggers(conn) -> None:
    """conn is a SQLAlchemy Connection."""
    for name, op, table in _TRIGGER_TABLE:
        conn.exec_driver_sql(
            f"""
            CREATE TRIGGER IF NOT EXISTS {name}
            BEFORE {op} ON {table}
            BEGIN
                SELECT RAISE(ABORT, '{table} is append-only');
            END;
            """
        )