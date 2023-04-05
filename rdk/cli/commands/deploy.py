import sys
from typing import Any, Callable, Dict, List, Optional


from rdk.utils.logger import get_main_logger
from rdk.core.rules_deploy import RulesDeploy


def run(rulenames: List[str], dryrun: bool):
    """
    test sub-command handler.
    """

    logger = get_main_logger()
    logger.info("RDK is starting ...")

    sys.exit(RulesDeploy(rulenames=rulenames, dryrun=dryrun).run())
