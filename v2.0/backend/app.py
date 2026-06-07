import logging
from functools import partial
from http.server import ThreadingHTTPServer

from .api import Api
from .config import Settings
from .database import Database
from .logging_config import configure_logging
from .rules import RuleRepository
from .server import SentinelHandler


def create_server(settings=None):
    settings = settings or Settings.from_env()
    configure_logging(settings.log_level)
    database = Database(settings.database)
    database.migrate()
    rules = RuleRepository(database)
    rules.seed_builtin_rules()
    api = Api(settings, database, rules)
    handler = partial(SentinelHandler, api=api, settings=settings)
    return ThreadingHTTPServer((settings.host, settings.port), handler)


def main():
    settings = Settings.from_env()
    server = create_server(settings)
    logging.getLogger("sentinelops").info(
        "SentinelOps v2 started at http://%s:%s", settings.host, settings.port
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
