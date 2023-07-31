import logging


def keep_logs() -> None:
    logging.basicConfig(
        filename="app.log",
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )