from pathlib import Path
from scan.yara.yara_tests import YaraConfig, TestsManager
from scan.yara.test_report import YaraReport
from utils.dir_manager import DirManager
from scan.bandit.scan import BanditScan
from score.calculate_scores import ScoreCalc
from report_format.report_homepage import HomePage
from utils.config import Config
from utils.log import Logger

config = Config()
logger = Logger(__name__, config["log_level"])()
target_dir = Path(config["target_dir"])


def debug_tests_database():
    """Run to fix errors or add bad tests to the exclude list in config"""
    tests = TestsManager(config, auto_init_rules=False)
    x = tests.identify_problematic_test_files()
    for i in x:
        logger.error(i)
    exit()


# @report_time_taken
def yara_scan():
    yara_config = YaraConfig()
    # yara_config.truncate_tests()
    yara_tests = TestsManager(yara_config)

    for package_dir in target_dir.iterdir():
        skip_package = package_dir.name in config["exclude_packages"]
        if package_dir.is_dir() and not skip_package:
            test_dir = DirManager(package_dir, exclude=config["exclude_in_packages"])
            results = yara_tests.run_all_on_dir(test_dir)
            (
                YaraReport(results, package_dir.name)
                .set_test_paths(yara_tests.config.dir.get_all_filenames())
                .preprocess_results()
                .truncate_testnames()
                .write_to_json()
                .populate_template()
            )


# @report_time_taken
def bandit_scan():
    BanditScan().load_packages().run_tests()
    ScoreCalc()()
    HomePage()()


if __name__ == "__main__":
    yara_scan()
    bandit_scan()
