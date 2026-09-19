# rasp_agent.py - middleware RASP simplificado (Flask/WSGI) para la app objetivo
import re, functools, logging
from flask import abort

SQLI_PATTERN = re.compile(r"(\bUNION\b|\bOR\b\s+1=1|--|;\s*DROP\b)", re.I)
logger = logging.getLogger('rasp')

def rasp_guard_query(query_builder_func):
    """Decorador que envuelve la construccion real de la consulta SQL
    con visibilidad del valor final ya concatenado -- despues de
    cualquier decodificacion previa."""
    @functools.wraps(query_builder_func)
    def wrapper(*args, **kwargs):
        final_query = query_builder_func(*args, **kwargs)
        if SQLI_PATTERN.search(final_query):
            logger.warning(
                'RASP: consulta SQL bloqueada en tiempo de ejecucion: %s',
                final_query,
            )
            abort(403, description='Operacion bloqueada por RASP')
        return final_query
    return wrapper
